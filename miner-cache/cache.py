import asyncio
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

logger = setupLogging()


def get_blocked_keys():
    try:
        with open("blocked_keys.txt", "r") as file:
            text = file.read()
            keys: List[str] = text.split("\n")
            return [key.strip() for key in keys if len(key)]
    except Exception:
        return []


async def sync_miners():
    metagraph = subtensor.metagraph(netuid=4)
    non_zero = sum([1 for x in metagraph.incentive if x])
    indices = numpy.argsort(metagraph.incentive)[-non_zero:]

    # Get the corresponding uids
    uids_with_highest_incentives: List[int] = metagraph.uids[indices].tolist()

    # get the axon of the uids
    axons: List[Tuple[bt.AxonInfo, int]] = [
        (metagraph.axons[uid], uid) for uid in uids_with_highest_incentives
    ]
    miner_models = {}
    for axon, uid in axons:
        headers = generate_header(hotkey, b"", axon.hotkey)
        try:
            res = httpx.get(
                f"http://{axon.ip}:{axon.port}/models",
                headers=headers,
                timeout=3,
            )
            if res.status_code != 200 or not isinstance(models := res.json(), list):
                continue
        except Exception:
            continue
        for model in models:
            if miner_models.get(model) is None:
                miner_models[model] = []
            m = {
                    "ip": axon.ip,
                    "port": axon.port,
                    "hotkey": axon.hotkey,
                    "coldkey": axon.coldkey,
                    "uid": uid,
                    "incentive_scaled": int(metagraph.incentive[uid] * 1000),
                }
            miner_models[model].append(m)
            print(m)
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
    subtensor = bt.subtensor("wss://entrypoint-finney.opentensor.ai:443")
    redis_host = os.getenv("REDIS_HOST", "cache")
    redis_port = int(os.getenv("REDIS_PORT", 6379))
    r = Redis(host=redis_host, port=redis_port, decode_responses=True)
    while True:
        asyncio.run(sync_miners())
