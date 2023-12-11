from mitmproxy import http

url = ""
file_name = "packets.txt"

def start(flow):
    global url
    url = flow.server.config.get("url")
    with open(file_name, "w") as file:
        pass

def request(flow: http.HTTPFlow) -> None:
    global url
    query = flow.request.query
    query.keys()
    if url in flow.request.pretty_host:
        content_type = flow.request.headers.get("Content-Type", "")
        if "text" in content_type or "json" in content_type or "javascript" in content_type:
            #write the packet contents to a file for the other script to analyze
            with open(file_name, "a") as file:
                file.write(flow.request.content.decode(errors="ignore"))
                file.write("\n\n")


def response(flow: http.HTTPFlow) -> None:
    global url
    if url in flow.request.pretty_host:
        # write the packet contents to a file for the other script to analyze
        with open(file_name, "a") as file:
            file.write(flow.response.content.decode(errors="ignore"))
            file.write("\n\n")


