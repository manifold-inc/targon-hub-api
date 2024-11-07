import math
from pydantic import BaseModel, Enum
from fastapi import FastAPI
from accelerate.commands import estimate


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
        print(
            f"Tried to load `{model_name}` with `{library}` but a possible model to load was not found inside the repo."
        )
        return None

    total_size, _ = estimate.calculate_maximum_sizes(model)
    return math.ceil(bytes_to_mib(total_size) / 81000)


app = FastAPI()



class Request(BaseModel):
    model: str
    library_name: str


@app.post("/estimate")
async def post_estimate(req: Request):
    required = estimate_max_size(req.model, req.library_name)
    print(f"{req.model}: {required}")
    return {"required_gpus", required}, 200


@app.get("/")
def ping():
    return "", 200
