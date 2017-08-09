### About
`A(ttack)WPA` WPA2 brute force implementation in pure Go.
Supported hccap files (hashcat format) only.

### Build 
```
go build
```

### Example (dictionary)
```
awpa.exe -hs example.hccap -w wifimaps-wordlist.txt
```

### Output
```
2017/08/09 14:16:51 Current speed: 3
2017/08/09 14:16:57 Current speed: 652
2017/08/09 14:17:00 Found password: Password
```

### Example (check a single password) 
```
awpa.exe -hs example.hccap -p Password
```

### Output
```
Password is valid
```