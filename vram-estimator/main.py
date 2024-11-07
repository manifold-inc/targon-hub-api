import math
from pydantic import BaseModel
from fastapi import FastAPI


from accelerate.commands import estimate


def bytes_to_mib(bytes_value):
    mib_value = bytes_value / (1024**2)  # 1024^2 = 1,048,576
    return math.ceil(mib_value)


def estimate_max_size(model_name):
    "Returns size in MiB, what nvidia smi prints"
    try:
        model = estimate.create_empty_model(
            model_name, library_name="transformers", trust_remote_code=False
        )
    except (RuntimeError, OSError) as e:
        library = estimate.check_has_model(e)
        if library != "unknown":
            raise RuntimeError(
                f"Tried to load `{model_name}` with `{library}` but a possible model to load was not found inside the repo."
            )
        return None

    total_size, _ = estimate.calculate_maximum_sizes(model)
    return max(bytes_to_mib(total_size) / 81000)


app = FastAPI()


class Request(BaseModel):
    model: str


@app.post("/estimate")
async def post_estimate(req: Request):
    return {"required_gpus", estimate_max_size(req.model)}


@app.get("/")
def ping():
    return "", 200
