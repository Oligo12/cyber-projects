# Kill by PID (Sentinel -> Webhook -> Velociraptor)

## What it does
On a Sentinel alert, extract a PID and POST it to a Velociraptor webhook to terminate the process.

## Flow (as implemented)
1) **Microsoft Sentinel alert** - webhook trigger fires on new alert.
2) **CD** - `Compose` parses `"Custom Details"` to JSON (falls back to `{}` if missing).
3) **PID** - `Compose` takes **the first value from** `Custom Details.process_id`  
4) **HTTP** - POST to the Velociraptor webhook with headers (`X-Auth-Token`) and body `{ client_id, pid, really }`.

Velociraptor Artifact used: Windows.Remediation.Process.

## Limitations
- No fallback to `pid` or `Entities[].ProcessId`. If `process_id` is absent/empty, the PID will be null (and `@int(...)` may coerce to 0).

## Future Work
- Add parent process check, correlate computer names with Velociraptor client names, so it's not hardcoded.

## Expected input shape
The playbook expects `Custom Details` to look like:
```json
{ "process_id": [3112] }
```

# Playbook flow (Designer)

![kill process playbook screenshot](/detection-lab/images/kppb.png)                                                                                                                                    
*Screenshot of the Sentinel Logic App GUI*

## CD body
- Designer (expression box)
```
json(
  if(
    equals(triggerBody()?['ExtendedProperties']?['Custom Details'], null),
    '{}',
    triggerBody()?['ExtendedProperties']?['Custom Details']
  )
)
```

## PID body
- Designer (expression box)
```
string(first(json(string(outputs('CD')))?['process_id']))
```

## HTTP body (cast to int)
- Designer (expression box)
```
{
  "client_id": "C.c17adc757b0f792c",
  "pid": @{int(outputs('PID'))},
  "really": true
}
```




