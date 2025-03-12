import math
from pydantic import BaseModel
import os
import json
from typing import List, Optional, Dict, Any
from fastapi import FastAPI
from accelerate.commands import estimate
import requests
from logconfig import setupLogging
import pymysql

logger = setupLogging()

# Constants
SUPPORTED_LIBRARIES = ["transformers", "timm"]
MODALITIES = ["text-generation"]
MAX_GPUS = 8

pymysql.install_as_MySQLdb()
# Database connection
db = pymysql.connect(
    host=os.getenv("HUB_DATABASE_HOST"),
    user=os.getenv("HUB_DATABASE_USERNAME"),
    passwd=os.getenv("HUB_DATABASE_PASSWORD"),
    db=os.getenv("HUB_DATABASE_NAME"),
    autocommit=True,
    ssl={"ssl_ca": "/etc/ssl/certs/ca-certificates.crt"},
)


def ensure_connection():
    """
    Checks if the database connection is alive and reconnects if necessary.
    """
    global db
    try:
        logger.info("Checking database connection health...")
        db.ping(reconnect=True)
        logger.info("Database connection is healthy")
    except (pymysql.Error, pymysql.OperationalError) as e:
        logger.warning(
            f"Database connection lost: {str(e)}, creating new connection..."
        )
        # If ping fails, create a new connection
        db = pymysql.connect(
            host=os.getenv("HUB_DATABASE_HOST"),
            user=os.getenv("HUB_DATABASE_USERNAME"),
            passwd=os.getenv("HUB_DATABASE_PASSWORD"),
            db=os.getenv("HUB_DATABASE_NAME"),
            autocommit=True,
            ssl={"ssl_ca": "/etc/ssl/certs/ca-certificates.crt"},
        )
        logger.info("New database connection established successfully")


def bytes_to_mib(bytes_value):
    mib_value = bytes_value / (1024**2)  # 1024^2 = 1,048,576
    return math.ceil(mib_value)


def estimate_max_size(model_name, lib):
    "Returns size in MiB, what nvidia smi prints"
    try:
        model = estimate.create_empty_model(
            model_name, library_name=lib, trust_remote_code=False
        )
    except (RuntimeError, OSError) as e:
        library = estimate.check_has_model(e)
        logger.error(
            f"Tried to load `{model_name}` with `{library}` but a possible model to load was not found inside the repo."
        )
        return None

    total_size, _ = estimate.calculate_maximum_sizes(model)
    return math.ceil(bytes_to_mib(total_size) / 81000)


app = FastAPI()


class Request(BaseModel):
    model: str
    library_name: str


def get_model_description(organization: str, model_name: str) -> str:
    try:
        response = requests.get(
            f"https://huggingface.co/{organization}/{model_name}/raw/main/README.md",
            timeout=10,
        )

        if not response.ok:
            return "No description provided"

        content = response.text
        # Skip YAML frontmatter if it exists
        if content.startswith("---"):
            parts = content.split("---", 2)
            if len(parts) >= 3:
                content = parts[2]

        # Split into lines and find first real paragraph
        lines = content.split("\n")
        paragraph_lines: List[str] = []

        for line in lines:
            line = line.strip()
            # Skip empty lines, headings, and common markdown elements
            if not line or line.startswith(("#", "---", "|", "```", "<!--", "- ")):
                if paragraph_lines:
                    break  # We found a paragraph, stop at next special element
                continue
            paragraph_lines.append(line)

        if paragraph_lines:
            return " ".join(paragraph_lines)

    except Exception as e:
        logger.error(f"Error fetching README: {str(e)}")

    return "No description provided"


def validate_and_prepare_model(model_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    try:
        model_id = model_data["id"]
        organization, model_name = model_id.split("/", 1)
        config = model_data.get("config", {})
        supported = True
        needs_custom_build = False
        required_gpus = 0

        if not model_name or not organization:
            logger.error(f"Invalid model ID format: {model_id}")
            return None

        # Check if model is private/gated
        if model_data.get("private", False) or model_data.get("gated", False):
            logger.info(f"Model {model_id} is private or gated")
            supported = False

        # Check modality
        pipeline_tag = model_data.get("pipeline_tag")
        if not pipeline_tag or pipeline_tag not in MODALITIES:
            logger.info(f"Model {model_id} has unsupported modality: {pipeline_tag}")
            supported = False

        # Check library
        library_name = model_data.get("library_name")
        if not library_name:
            logger.info(f"Model {model_id} does not have any library metadata")
            supported = False
        elif library_name not in SUPPORTED_LIBRARIES:
            logger.info(f"Library {library_name} for model {model_id} is not supported")
            supported = False

        # Check if model requires trust_remote_code from config
        if config.get("trust_remote_code", False):
            logger.info(f"Model {model_id} needs custom build (from config)")
            needs_custom_build = True
            supported = False
        else:
            try:
                required_gpus = estimate_max_size(model_id, library_name) or 0
                if required_gpus > MAX_GPUS:
                    logger.info(
                        f"Model {model_id} has invalid GPU requirement: {required_gpus}"
                    )
                    supported = False
            except Exception as e:
                logger.error(f"GPU estimation error for {model_id}: {str(e)}")
                supported = False

        model_desc = get_model_description(organization, model_name)
        has_chat_template = (
            config.get("tokenizer_config", {}).get("chat_template") is not None
        )
        supported_endpoints = (
            ["COMPLETION", "CHAT"] if has_chat_template else ["COMPLETION"]
        )

        return {
            "name": model_id,
            "modality": pipeline_tag,
            "required_gpus": 0 if needs_custom_build else required_gpus,
            "supported_endpoints": json.dumps(supported_endpoints),
            "cpt": 0 if needs_custom_build else required_gpus,
            "enabled": False,
            "custom_build": needs_custom_build,
            "description": model_desc,
            "supported": supported,
        }

    except Exception as e:
        logger.error(f"Error validating {model_id}: {str(e)}")
        return None


def fetch_model_data(
    model_id: Optional[str] = None,
):
    response = requests.get(f"https://huggingface.co/api/models/{model_id}")
    if not response.ok:
        logger.error(
            f"Failed to fetch {model_id} model: {response.status_code} - {response.text}"
        )
        return None

    model_data = response.json()
    logger.info(f"Fetched {model_id} model")
    return model_data


def check_model_in_db(model_id: str):
    try:
        ensure_connection()
        with db.cursor() as cursor:
            # Get existing model id and required_gpus
            cursor.execute(
                "SELECT id, required_gpus FROM model WHERE name = %s", (model_id,)
            )
            result = cursor.fetchone()

            if result is not None:
                model_id, required_gpus = result
                return model_id, required_gpus
            else:
                return None, None
    except Exception as e:
        logger.error(f"Error checking model: {model_id}: {str(e)}")
        return None, None


def add_to_db(processed_data: Dict[str, Any]):
    try:
        ensure_connection()
        with db.cursor() as cursor:
            insert_query = """
            INSERT INTO model (
                name, description, modality, supported_endpoints,
                cpt, enabled, required_gpus, custom_build, supported, created_at
            ) VALUES (
                %(name)s, %(description)s, %(modality)s, %(supported_endpoints)s,
                %(cpt)s, %(enabled)s, %(required_gpus)s, %(custom_build)s, %(supported)s, NOW()
            )
            """
            cursor.execute(insert_query, processed_data)
            if cursor.rowcount == 1:
                logger.info(
                    f"Adding new model: {processed_data['name']} (custom_build: {processed_data['custom_build']})"
                )
            else:
                logger.debug(f"Unable to add model: {processed_data['name']}")
    except Exception as e:
        logger.error(f"Unexpected error in add_to_db: {e}")


@app.post("/")
async def post_estimate(req: Request):
    model_id, required_gpu = check_model_in_db(req.model)
    if model_id is not None:
        return {"required_gpus": required_gpu}

    model_data = fetch_model_data(req.model)
    if model_data is None:
        return {"required_gpus": 0}

    processed_data = validate_and_prepare_model(model_data)
    if processed_data == None:
        return {"required_gpus": 0}
    add_to_db(processed_data)

    required_gpu = processed_data["required_gpus"]
    logger.info(f"{req.model}: {required_gpu}")
    return {"required_gpus": required_gpu}


@app.get("/")
def ping():
    return ""
