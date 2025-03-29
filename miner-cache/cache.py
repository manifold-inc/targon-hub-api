import asyncio
import aiohttp
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

logger = setupLogging()

DEBUG = os.getenv("DEBUG", False)


async def get_models(session, hotkey, axon) -> Tuple[Dict[str, int], Optional[str]]:
    headers = generate_header(hotkey, b"", axon.hotkey)
    try:
        async with session.get(
            f"http://{axon.ip}:{axon.port}/models",
            headers=headers,
            timeout=10,
        ) as res:
            if res.status != 200:
                return {}, f"status code {res.status}"
            models = await res.json()
            if not isinstance(models, dict):
                return {}, f"Response is not dict"
            return models, None
    except Exception as e:
        return {}, f"{e}, {type(e)}"


async def send_uid_info_to_jugo(session: aiohttp.ClientSession, data: List[Dict]):
    if DEBUG:
        return
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


async def get_infos(
    uid, session, hotkey, axon
) -> Tuple[int, Any, Dict[str, int], Dict, Optional[str]]:
    models, err = await get_models(session, hotkey, axon)
    jugo_info = {
        "uid": uid,
        "data": {
            "miner_cache": {
                "models_error": err,
                "models": models,
            },
        },
    }
    return uid, axon, models, jugo_info, err


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
    task_responses: List[Tuple[int, Any, Dict[str, int], Dict, str]] = []
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
    for uid, axon, models, jugo_info, err in task_responses:
        jugo_info_list.append(jugo_info)
        if err != None:
            logger.error(f"UID {uid}: {err}")
        else:
            logger.info(f"UID {uid}: {models}")
        for model, qps in models.items():
            redis_miner_data = {
                "ip": axon.ip,
                "port": axon.port,
                "hotkey": axon.hotkey,
                "coldkey": axon.coldkey,
                "uid": uid,
                "weight": min(1000, qps),
            }
            if miner_models.get(model) is None:
                miner_models[model] = []
            miner_models[model].append(redis_miner_data)

    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=5)) as session:
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
