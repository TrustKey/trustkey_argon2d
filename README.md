### trustkey_argon2d
[Promise][0]-based TrustKey supervisor module. Generates array of random bytes based on trustkey. Uses argon2d as a minimum time of evaluation function to prove that server cannot proceed attack in order to affect final trustkey by posting fake hashes and trying to find set of inputs which give certain result in consuming trustkey function. Using of time-cost functions with certain parameters can prove that server couldn't calculate even a single seed for top-level function during round time. 

Based on [argon2][1].

###Module usage examples with [supervisor][2] repl interface

#### Constructing promise:
Request:
```javascript
‌‌‌‌services.promise.resolve({
      "_f": "trustkey_argon2d_constructor",
      "server_id": "D000000000000000",
      "trustkey_ts": 1520364270,
      "time_cost": 20,
      "memory_cost": 3,
      "parallelism": 1,
      "n_bytes": 64,
      "b64_buffers": true
  }, (res) => console.log(res))
```

`Argon2 parameters are shown as an example. The only possible attacker is the server therefore secure parameters should be chosen by users`

Response:
```json
{ "success": true,
  "result": 
   { "_f": "trustkey_argon2d",
     "server_id": "D000000000000000",
     "trustkey_ts": 1520364270,
     "time_cost": 20,
     "memory_cost": 3,
     "parallelism": 1,
     "b64_buffers": true,
     "seed": "ScmnLtFrnCxaLW5FRipvJEDZ6VZ8k9HFxR6l0esIpWx3sRV6uNJI+FqFfmcSHDZokBvuXBrdgopoX+9GlIRaEA==" } }
```

#### Resolve promise:
Request:
```javascript
//Based on previous response
‌‌services.promise.resolve({ "_f": "trustkey_argon2d",
    "server_id": "D000000000000000",
    "trustkey_ts": 1520364270,
    "time_cost": 20,
    "memory_cost": 3,
    "parallelism": 1,
    "b64_buffers": true,
    "seed": "ScmnLtFrnCxaLW5FRipvJEDZ6VZ8k9HFxR6l0esIpWx3sRV6uNJI+FqFfmcSHDZokBvuXBrdgopoX+9GlIRaEA==" }, (res) => console.log(res))
```
Response:
```json
{ "success": true,
  "result": "DQMB53Dk2pw0lfJN1oyTxWbKLpaLhFQ6bSS5PxS8vwtULVGzfWgAtlRt/PPeGJSGFVabfBroBhfJgGiGvx7WDg==" }
```

Error response example(error codes listed in `errorCodes.js`):
```json
{"success":false,"error_code":6,"error":"trustkey not found"}
```

[0]: https://github.com/TrustKey/promise
[1]: https://www.npmjs.com/package/argon2
[2]: https://github.com/TrustKey/supervisor