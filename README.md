# RPC - Remote Procedure Calls

## MG-RPC frame format

#### Request frame format

```json
{
  "method": "Math.Add",     // Required. Function name to invoke.
  "args": {                 // Optional. Call arguments
    "a": 1,
    "b": 2
  },
  "src": "joe/32efc823aa",  // Optional. Used with MQTT (a response topic)
  "tag": "hey!",            // Optional. Any arbitrary string. Will be repeated in the response
  "id": 1772                // Optional. Numeric frame ID.
}
```

#### Successful response frame format

```json
{
  "result": { ... },        // Required. Call result
  "tag": "hey!"             // Optional. Present if request contained "tag"
}
```

####  Failure response frame format

```json
{
  "error": {
    "code": 123,
    "message": "oops"
  }
}
```

If the `error` key is present in the response, it's a failure. Failed
response may also contain a `result`, in order to pass more specific
information about the failure.

