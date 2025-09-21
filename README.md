
# 🦾 Hacking Tricks

A living list of real-world hacking tricks, tips, and one-liners. Add your own methods, tools, and dirty hacks as you go.  
**_For research, education, and CTFs only. Don’t be a script kiddie. Stay leet._**

---

## 🛠️ Tricks

### 1. Masscan for Open Proxies (Exclude Private IPs)

Find open proxies (8080, 3128, 1080, 8000, 8888) on the entire IPv4 internet, skipping all private/reserved IP ranges:


```
sudo masscan 0.0.0.0/0 -p8080,3128,1080,8000,8888 --rate=10000 -oG found_proxies.gnmap \
  --exclude 10.0.0.0/8 \
  --exclude 127.0.0.0/8 \
  --exclude 172.16.0.0/12 \
  --exclude 192.168.0.0/16 \
  --exclude 224.0.0.0/4 \
  --exclude 240.0.0.0/4 \
  --exclude 0.0.0.0/8 \
  --exclude 100.64.0.0/10 \
  --exclude 169.254.0.0/16 \
  --exclude 255.255.255.255
````
### resuming scan afte cancel with control + C
```
1. add # before this

nocapture = servername

after
#nocapture = servername
then save

```
```
sudo masscan --resume paused.conf \
  --exclude 10.0.0.0/8 \
  --exclude 127.0.0.0/8 \
  --exclude 172.16.0.0/12 \
  --exclude 192.168.0.0/16 \
  --exclude 224.0.0.0/4 \
  --exclude 240.0.0.0/4 \
  --exclude 0.0.0.0/8 \
  --exclude 100.64.0.0/10 \
  --exclude 169.254.0.0/16 \
  --exclude 255.255.255.255


```

***convert for hydra*** 

```
awk -F'Host: | \\(|Ports: |/open' '
{
  if ($2 && $4) {
    ip=$2
    split($4,ports,",")
    for (i in ports) {
      match(ports[i],/[0-9]+/)
      if (RSTART) print ip ":" substr(ports[i],RSTART,RLENGTH)
    }
  }
}' found_telnet.gnmap > hydra_targets.txt
```




**Explanation:**

* **`masscan 0.0.0.0/0`**: Scan the whole IPv4 internet.
* **`-p8080,3128,1080,8000,8888`**: Scan common proxy ports.
* **`--rate=10000`**: 10k packets/sec (edit if you get network drops).
* **`-oG found_proxies.gnmap`**: Output in greppable format.
* **`--exclude ...`**: Skips private/reserved IP ranges, avoids legal/ISP drama, saves time.
* **`--resume ...`**: resumes with what you exlude and the path to your resume config <3.


## 🧑‍💻 Contributing

Feel free to fork, PR, or drop your favorite tricks and one-liners!

> **Warning:**
> All content here is for educational purposes. You are responsible for your own actions.
> *Hack the planet, not your neighbor’s toaster.*
