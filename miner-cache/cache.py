import asyncio
import aiohttp
import uuid
from typing import List, Tuple
import os
import bittensor as bt
from redis import Redis
from redis.commands.json.path import Path
import json
from hashlib import sha256
from uuid import uuid4
from math import ceil
from typing import Any, Dict, List, Optional, Union
import time
from substrateinterface import Keypair
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


async def get_models(session, hotkey, axon) -> List[str]:
    headers = generate_header(hotkey, b"", axon.hotkey)
    try:
        async with session.get(
            f"http://{axon.ip}:{axon.port}/models",
            headers=headers,
            timeout=3,
        ) as res:
            if res.status != 200:
                return []
            models = await res.json()
            if not isinstance(models, list):
                return []
            return models
    except Exception:
        return []


async def get_gpus(session, hotkey, axon) -> Tuple[int, Optional[Dict], Optional[str]]:
    nonce = str(uuid.uuid4())
    req_body = {"nonce": nonce}
    req_bytes = json.dumps(
        req_body, ensure_ascii=False, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")
    headers = generate_header(hotkey, req_bytes, axon.hotkey)
    gpus = {"h100": 0, "h200": 0}
    try:
        async with session.post(
            f"http://{axon.ip}:{axon.port}/nodes",
            headers=headers,
            data=req_bytes,
            timeout=aiohttp.ClientTimeout(total=20),
        ) as res:
            if res.status != 200:
                return 0, None, f"Bad status code: {res.status}"
            nodes = await res.json()
            if not isinstance(nodes, list):
                return 0, None, f"response not list"
            weight = 0
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
                    weight += 1 * num_gpus
                    gpus["h100"] += 1 * num_gpus
                    continue
                weight += 2 * num_gpus
                gpus["h200"] += 1 * num_gpus

            return weight, gpus, None
    except Exception as e:
        return 0, None, f"Unknown error: {e}"


async def send_uid_info_to_jugo(session: aiohttp.ClientSession, data: List[Dict]):
    req_bytes = json.dumps(
        data, ensure_ascii=False, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")
    headers = generate_header(hotkey, req_bytes, "")
    headers["X-Targon-Service"] = "targon-hub-api"
    async with session.post(
        url="https://jugo.targon.com/mongo", headers=headers, data=req_bytes
    ) as res:
        if res.status == 200:
            return
        text = await res.text()
    logger.error(f"Failed sending to jugo: {text}")


async def get_infos(uid, session, hotkey, axon):
    weight, gpus, err = await get_gpus(session, hotkey, axon)
    models = await get_models(session, hotkey, axon)
    jugo_info = {
        "uid": uid,
        "data": {
            "miner_cache": {
                "weight": weight,
                "nodes_endpoint_error": err,
                "models": models,
                "gpus": gpus,
            },
        },
    }
    return uid, axon, weight, models, jugo_info, err


async def sync_miners():
    metagraph = subtensor.metagraph(netuid=4)

    # Get the corresponding uids
    uids_with_highest_incentives: List[int] = metagraph.uids.tolist()

    # get the axon of the uids
    axons: List[Tuple[bt.AxonInfo, int]] = [
        (metagraph.axons[uid], uid) for uid in uids_with_highest_incentives
    ]
    miner_models = {}

    tasks = []
    task_responses = []
    async with aiohttp.ClientSession(
        timeout=aiohttp.ClientTimeout(total=20)
    ) as session:
        i = 0
        for axon, uid in axons:
            logger.info(f"Pinging {uid}")
            i += 1
            if i % 100 == 0:
                responses = await asyncio.gather(*tasks)
                task_responses.extend(responses)
                tasks = []
            tasks.append(get_infos(uid, session, hotkey, axon))
        if len(tasks) != 0:
            responses = await asyncio.gather(*tasks)
            task_responses.extend(responses)
            tasks = []

    jugo_info_list = []
    for uid, axon, weight, models, jugo_info, err in task_responses:
        jugo_info_list.append(jugo_info)
        redis_miner_data = {
            "ip": axon.ip,
            "port": axon.port,
            "hotkey": axon.hotkey,
            "coldkey": axon.coldkey,
            "uid": uid,
            "weight": weight,
        }
        logger.info(redis_miner_data)
        if err != None:
            logger.error(err)
        for model in models:
            if miner_models.get(model) is None:
                miner_models[model] = []
            miner_models[model].append(redis_miner_data)

    async with aiohttp.ClientSession(
        timeout=aiohttp.ClientTimeout(total=20)
    ) as session:
        await send_uid_info_to_jugo(session, jugo_info_list)
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
    subtensor = bt.subtensor(
        os.getenv("SUBTENSOR_WS_ADDR", "ws://subtensor.sybil.com:9944")
    )
    redis_host = os.getenv("REDIS_HOST", "cache")
    redis_port = int(os.getenv("REDIS_PORT", 6379))
    r = Redis(host=redis_host, port=redis_port, decode_responses=True)
    while True:
        asyncio.run(sync_miners())
