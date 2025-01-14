import asyncio
import base64
from dataclasses import dataclass
import getpass
from typing import TypedDict, List
from urllib.parse import urlencode
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import requests


base_url = "https://aml.blocksec.com"

code_message: dict[int, str] = {
    200000: "Success",
    400001: "Unauthorized operation",
    400002: "Request rate is too high. Please try again later.",
    400004: "Invalid params",
    400005: "User does not exist",
    400006: "Server busy", 
    400007: "Invalid API key",
    400008: "Invalid auth format",
    400009: "The API key is expired",
    400010: "404 not found!",
    400011: "Invalid address. Please ensure that you have provided the correct chain and address.",
    400012: "Daily request limit exceeded. Please try again tomorrow.",
    400013: "Invalid params. Unsupported chain name",
    500000: "Internal error"
}

@dataclass
class ResponseData[D]:
    request_id: str
    code: int
    message: str
    data: D | None
    
    @classmethod
    def from_json(cls, json_data: dict) -> "ResponseData[D]":
        return cls(
            request_id=json_data["request_id"],
            code=json_data["code"],
            message=json_data["message"],
            data=json_data.get("data")
        )


ChainInfo = TypedDict("ChainInfo", {
    "chain_id": int,
    "chain_name": str,
})

EntityCategory = TypedDict("EntityCategory", {
    "name": str,
    "code": int,
})

EntityAttribute = TypedDict("EntityAttribute", {
    "name": str,
    "code": int,
    "comp_info": List[str],
})

EntityDescription = TypedDict("EntityDescription", {
    "website": str,
    "twitter": str,
    "telegram": str,
    "discord": str,
})

Entity = TypedDict("Entity", {
    "entity": str,
    "categories": List[EntityCategory],
    "attributes": List[EntityAttribute] | None,
    "description": EntityDescription,
})

AddressLabelInfo = TypedDict("AddressLabelInfo", {
    "chain_id": int,
    "address": str,
    "main_entity": str,
    "main_entity_info": Entity,
    "comp_entities": List[str],
    "attributes": List[EntityAttribute],
    "name_tag": str,
})

OneChainLabelInfoBatch = TypedDict("OneChainLabelInfoBatch", {
    "chain_id": int,
    "addresses": List[AddressLabelInfo],
})


class AmlClient:

    def __init__(self, *, api_key: str=None, api_key_file: str=None, aes_256_hex_key: str=None):
        if api_key_file:
            with open(api_key_file, "r") as f:
                api_key = f.read()
                api_key = api_key.strip("\n\t\r ")
        if not aes_256_hex_key:
            aes_256_hex_key = getpass.getpass("Enter AmlClinet API-KEY AES-256 hex key(if not encrypted, enter empty): ")
        if aes_256_hex_key:
            if len(aes_256_hex_key) != 64:
                raise Exception("Hex key must be 64 characters long")
            encrypted_bytes = base64.b64decode(api_key.encode('utf-8'))
            iv = encrypted_bytes[:AES.block_size]
            ciphertext = encrypted_bytes[AES.block_size:]
            cipher = AES.new(bytes.fromhex(aes_256_hex_key), AES.MODE_CBC, iv)
            decrypted_bytes = unpad(cipher.decrypt(ciphertext), AES.block_size)
            api_key = decrypted_bytes.decode('utf-8')
        self._headers = {"content-type": "application/json", "API-KEY": api_key}
        
    async def get[D](self, path: str, params: dict=None) -> D:
        url = f"{base_url}/{path.strip('/')}"
        if params:
            url = f"{url}?{urlencode(params)}"
        resp = await asyncio.to_thread(requests.get, url, headers=self._headers)
        status_code = resp.status_code
        if resp.content:
            data = ResponseData[D].from_json(resp.json())
            if data.code is 200000:
                return data.data
            else:
                raise Exception(f"Request failed with status code {status_code}, code {data.code} and message {data.message}")
        raise Exception(f"Request failed with status code {status_code}")
        
    async def post[D](self, path: str, body: dict=None) -> D:
        url = f"{base_url}/{path}"
        resp = await asyncio.to_thread(requests.post, url, headers=self._headers, json=body)
        status_code = resp.status_code
        if resp.content:
            data = ResponseData[D].from_json(resp.json())
            if data.code is 200000:
                return data.data
            else:
                raise Exception(f"Request failed with status code {status_code}, code {data.code} and message {data.message}")
        raise Exception(f"Request failed with status code {status_code}")

    async def chain_list(self) -> List[ChainInfo]:
        return await self.get("/address-label/api/v3/chain-list")
    
    async def entity_info(self, entity: str) -> Entity:
        return await self.post("/address-label/api/v3/entity", {"entity": entity})
    
    async def address_label(self, chain_id: int, address: str) -> AddressLabelInfo:
        return await self.post("/address-label/api/v3/labels", {"chain_id": chain_id, "address": address})
    
    async def addresses_label_batch(self, chain_id: int, addresses: List[str]) -> List[AddressLabelInfo]:
        return await self.post("/address-label/api/v3/labels/batch", {"chain_id": chain_id, "addresses": addresses})
    
    async def addresses_multi_chain_label_batch(self, chain_ids: List[int], addresses: List[str]) -> List[OneChainLabelInfoBatch]:
        return await self.post("/address-label/api/v3/labels/multi-chain-batch", {"chain_ids": chain_ids, "addresses": addresses})
