import asyncio
import uuid
from typing import List, Tuple
import os
import bittensor as bt
from redis import Redis
from redis.commands.json.path import Path
import numpy
import json
from hashlib import sha256
from uuid import uuid4
from math import ceil
from typing import Any, Dict, List, Optional, Union
import time
from substrateinterface import Keypair
import httpx
from logconfig import setupLogging
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
import base64

logger = setupLogging()


def load_public_key():
    try:
        with open("./public_key.pem", "rb") as key_file:
            public_key = serialization.load_pem_public_key(key_file.read())
        return public_key
    except Exception as e:
        raise Exception(f"Error loading public key: {e}")


PUBKEY = load_public_key()


def verify_signature(msg: dict, signature: str, public_key):
    try:
        msg_bytes = json.dumps(msg, separators=(",", ":")).encode("utf-8")

        signature_bytes = base64.b64decode(signature)

        public_key.verify(
            signature_bytes,
            msg_bytes,
            padding.PKCS1v15(),
            hashes.SHA256(),
        )

        return True
    except Exception:
        return False


def get_models(hotkey, axon):
    headers = generate_header(hotkey, b"", axon.hotkey)
    try:
        res = httpx.get(
            f"http://{axon.ip}:{axon.port}/models",
            headers=headers,
            timeout=3,
        )
        if res.status_code != 200:
            return []
        models = res.json()
        if not isinstance(models, list):
            return []
        return models
    except Exception:
        return []


def get_gpus(hotkey, axon):
    nonce = str(uuid.uuid4())
    req_body = {"nonce": nonce}
    req_bytes = json.dumps(
        req_body, ensure_ascii=False, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")
    headers = generate_header(hotkey, req_bytes, axon.hotkey)
    try:
        res = httpx.post(
            f"http://{axon.ip}:{axon.port}/nodes",
            headers=headers,
            json=req_body,
            timeout=30,
        )
        if res.status_code != 200:
            return 0
        nodes = res.json()
        if not isinstance(nodes, list):
            return 0
        gpus = 0
        for node in nodes:
            if not isinstance(node, dict):
                continue
            msg = node.get("msg")
            signature = node.get("signature")
            if not isinstance(msg, dict):
                continue
            if not isinstance(signature, str):
                continue
            if not verify_signature(msg, signature, PUBKEY):
                continue
            miner_nonce = msg.get("nonce")
            if miner_nonce != nonce:
                continue
            gpu_info = msg.get("gpu_info", [])
            if len(gpu_info) == 0:
                continue
            is_h100 = "h100" in gpu_info[0].get("gpu_type", "").lower()
            is_h200 = "h200" in gpu_info[0].get("gpu_type", "").lower()
            if not is_h100 and not is_h200:
                continue
            num_gpus = msg.get("no_of_gpus", 0)
            if is_h100:
                gpus += num_gpus
                continue
            gpus += num_gpus * 2

        return gpus
    except Exception as e:
        print(e)
        return 0


async def sync_miners():
    metagraph = subtensor.metagraph(netuid=4)
    non_zero = sum([1 for _ in metagraph.incentive])
    indices = numpy.argsort(metagraph.incentive)[-non_zero:]

    # Get the corresponding uids
    uids_with_highest_incentives: List[int] = metagraph.uids[indices].tolist()

    # get the axon of the uids
    axons: List[Tuple[bt.AxonInfo, int]] = [
        (metagraph.axons[uid], uid) for uid in uids_with_highest_incentives
    ]
    miner_models = {}
    for axon, uid in axons:
        models = get_models(hotkey, axon)
        gpus = get_gpus(hotkey, axon)
        for model in models:
            if miner_models.get(model) is None:
                miner_models[model] = []
            m = {
                "ip": axon.ip,
                "port": axon.port,
                "hotkey": axon.hotkey,
                "coldkey": axon.coldkey,
                "uid": uid,
                "weight": gpus,
            }
            miner_models[model].append(m)
        print(uid, models, gpus)
    for model in miner_models.keys():
        r.json().set(model, obj=miner_models[model], path=Path.root_path())
    await asyncio.sleep(60 * 30)


def generate_header(
    hotkey: Keypair,
    body: Union[Dict[Any, Any], List[Any], bytes],
    signed_for: Optional[str] = None,
) -> Dict[str, Any]:
    timestamp = round(time.time() * 1000)
    timestampInterval = ceil(timestamp / 1e4) * 1e4
    uuid = str(uuid4())
    req_hash = None
    if isinstance(body, bytes):
        req_hash = sha256(body).hexdigest()
    else:
        req_hash = sha256(json.dumps(body).encode("utf-8")).hexdigest()

    headers = {
        "Epistula-Version": str(2),
        "Epistula-Timestamp": str(timestamp),
        "Epistula-Uuid": uuid,
        "Epistula-Signed-By": hotkey.ss58_address,
        "Epistula-Request-Signature": "0x"
        + hotkey.sign(f"{req_hash}.{uuid}.{timestamp}.{signed_for or ''}").hex(),
    }
    if signed_for:
        headers["Epistula-Signed-For"] = signed_for
        headers["Epistula-Secret-Signature-0"] = (
            "0x" + hotkey.sign(str(timestampInterval - 1) + "." + signed_for).hex()
        )
        headers["Epistula-Secret-Signature-1"] = (
            "0x" + hotkey.sign(str(timestampInterval) + "." + signed_for).hex()
        )
        headers["Epistula-Secret-Signature-2"] = (
            "0x" + hotkey.sign(str(timestampInterval + 1) + "." + signed_for).hex()
        )
    return headers


if __name__ == "__main__":
    hotkey = Keypair(
        ss58_address=os.getenv("HOTKEY", ""),
        public_key=os.getenv("PUBLIC_KEY", ""),
        private_key=os.getenv("PRIVATE_KEY", ""),
    )
    subtensor = bt.subtensor(os.getenv("SUBTENSOR_WS_ADDR", "ws://subtensor.sybil.com:9944"))
    redis_host = os.getenv("REDIS_HOST", "cache")
    redis_port = int(os.getenv("REDIS_PORT", 6379))
    r = Redis(host=redis_host, port=redis_port, decode_responses=True)
    while True:
        asyncio.run(sync_miners())
