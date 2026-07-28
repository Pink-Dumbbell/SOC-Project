import requests

url = "http://127.0.0.1:5001/startscan"

data = {
    "scanname": "Auto Test",
    "scantarget": "8.8.4.4",
    "usecase": "Footprint",
    "modulelist": "",
    "typelist": ""
}

response = requests.post(url, data=data, allow_redirects=False)

print("Status :", response.status_code)
print("Location :", response.headers.get("Location"))
