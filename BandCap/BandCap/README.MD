# BandCap

A system-wide bandwidth limiter for Windows 10/11 using Python and WinDivert



# 



# What I have to say:

### ⚠️ Disclaimer ⚠️: Claude AI coded this entire thing, do with this information what you will.

#### I really want to be transparent about AI usage here because I don't like people masquerading AI code as human-made, it's deceptive.

I'm still on ADSL, I live far up in the mountains, and I'm not alone in this house. Whenever some app decides to fetch a multi-hundred megabyte update or whenever I send a video to someone (which is a catastrophic event on ADSL), the internet becomes unbearably slow for not only me but also everyone else (presumably bufferbloat). 2008 internet too slow for 2026, shocker, I know. I just wanted something that could throttle my bandwidth system-wide on Windows 11, I didn't really feel like paying for NetLimiter and other polished apps alike, I just wanted a simple "click, and that's it, ur throttled now" option that didn't require a payment. And I absolutely suck at coding, hence why this whole thing was made with Claude AI from the ground up. Just look at all those comments scattered around the code, it's pretty obvious.
WinDivert throws off Bitdefender and VirusTotal a lot, since it needs admin, if you don't trust the included DLL and SYS file, then just go pick your own at their official repository over at ==> " https://github.com/basil00/WinDivert " <== (should be tucked into a folder somewhere in the zip file in their Releases page)
Only known issue as far as I can see are just the graphs sometimes getting stuck, but it gets fixed if you just click Stop and Start again. Also WinDivert is annoying and locks its files sometimes after you've run the program, in that case it needs a system restart to delete the folder. Also Bitdefender blocks the WinDivert.sys file for me, I had to create an exception in its settings, which I have to admit, is pretty annoying.
And that's really about it. There's not much more I have to say about this aside from the fact I'm happy that it works.









# Whatever Claude originally wrote in this README:

BandCap 2.0 - volatile system-wide bandwidth limiter (Windows 10/11, 64-bit Python 3.8+)

Run:      double-click BandCap.bat   (or: python bandcap.py)  -> asks for admin itself
CLI:      python bandcap.py --cli --down 8mbps --up 250kbps \[--mode fq|simple]
Tests:    python bandcap.py --selftest     offline logic + queue tests, no driver needed
Compare:  python simulate.py               Reno-flow simulation: simple FIFO vs fair queue + CoDel

Queue modes (Options menu):
Fair queue + CoDel  default. Per-connection queues, byte-fair round robin, CoDel drops
based on queueing delay. Low latency while the line stays full.
Simple FIFO         v1 behaviour: one tail-drop queue (+ priority lane for ACKs/DNS).

Volatile: no registry/firewall/QoS changes. Driver unloads when you press Stop or close
the window; if the process dies, Windows closes the handles and traffic is normal again.
While running: the WinDivert driver service is registered transiently and the system
timer resolution is raised to 1 ms (both undone on exit).

Uses WinDivert 2.2.2 (https://reqrypt.org/windivert.html), LGPLv3, unmodified x64
binaries from the official release WinDivert-2.2.2-A.zip
WinDivert.dll    sha256 c1e060ee19444a259b2162f8af0f3fe8c4428a1c6f694dce20de194ac8d7d9a2
WinDivert64.sys  sha256 8da085332782708d8767bcace5327a6ec7283c17cfb85e40b03cd2323a90ddc2





## License

BandCap's own code (bandcap.py, simulate.py, BandCap.bat) is released under the MIT License, see LICENSE.

WinDivert (WinDivert.dll, WinDivert64.sys) is © basil00 and used under the LGPLv3, see WinDivert-LICENSE.txt.

