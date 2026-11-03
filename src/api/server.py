import os

import uvicorn


def main():
    # Defaults to loopback: the API has no auth and holds router credentials in
    # flight. The Docker image sets ROUTER_SECURITY_HOST=0.0.0.0 so a published
    # port (-p 8000:8000) is reachable.
    host = os.environ.get("ROUTER_SECURITY_HOST", "127.0.0.1")
    port = int(os.environ.get("ROUTER_SECURITY_PORT", "8000"))
    uvicorn.run("api.main:app", host=host, port=port, reload=False)


if __name__ == "__main__":
    main()
