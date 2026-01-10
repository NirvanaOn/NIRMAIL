from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Optional
import base64
import binascii


from mail_engine import run_mail_check

app = FastAPI(title="NIRMAIL Backend")


class CheckRequest(BaseModel):
    domain: str
    sender_ip: str
    mail_from: Optional[str] = None
    helo: Optional[str] = None
    raw_email_b64: Optional[str] = None


from fastapi import HTTPException

@app.post("/check")
def check_mail(req: CheckRequest):
    raw_email = None

    if req.raw_email_b64:
        try:
            raw_email = base64.b64decode(req.raw_email_b64, validate=True)
        except binascii.Error:
            raise HTTPException(
                status_code=400,
                detail="Invalid base64-encoded raw_email"
            )

    try:
        return run_mail_check(
            domain=req.domain,
            sender_ip=req.sender_ip,
            mail_from=req.mail_from,
            helo=req.helo,
            raw_email=raw_email,
        )

    except HTTPException:
        raise   # re-raise clean HTTP errors

    except Exception:
        raise HTTPException(
            status_code=500,
            detail="Mail authentication processing failed"
        )
