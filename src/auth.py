from aws.api_gateway_types import HttpEvent


def is_authorized_read(event: HttpEvent, namespace: str) -> bool:
    return True


def is_authorized_write(event: HttpEvent, namespace: str) -> bool:
    return True