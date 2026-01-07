# Shadowsocks Resistance Against Detection and Blocking

Shadowsocks used to be blocked in some countries, and because Outline uses Shadowsocks, there has been skepticism about Outline working in those countries. In fact, people have tried Outline in the past and had their servers blocked.

However, since the second half of 2020 things have changed. The Outline team and Shadowsocks community made a number of improvements that strengthened Shadowsocks beyond the censor's current capabilities.

As shown in the research [How China Detects and Blocks Shadowsocks](https://gfw.report/talks/imc20/en/), the censor uses active probing to detect Shadowsocks servers. The probing may be triggered by packet sniffing, but that's not how the servers are detected.

Even though Shadowsocks is a standard, it leaves a lot of room for choices on how it's implemented and deployed.

First of all, you **must use AEAD ciphers**. The old stream ciphers are easy to break and manipulate, exposing you to simple detection and decryption attacks. Outline has banned all stream ciphers, since people copy old examples to set up their servers. The Outline Manager goes further and picks the cipher for you, since users don't usually know how to choose a cipher, and it generates a long random secret, so you are not vulnerable to dictionary-based attacks.

Second, you need **probing resistance**. Both shadowsocks-libev and Outline have added that. The research [Detecting Probe-resistant Proxies](https://www.ndss-symposium.org/ndss-paper/detecting-probe-resistant-proxies/) showed that, in the past, an invalid byte would trigger different behaviors whether it was inserted in positions 49, 50 or 51 of the stream, which is very telling. That behavior is now gone, and the censor can no longer rely on that.

Third, you need **protection against replayed data**. Both shadowsocks-libev and Outline have added such protection, which you may need to enable explicitly on ss-libev, but it's the default on Outline.

Fourth, Outline and clients using shadowsocks-libev now **merge the SOCKS address and the initial data** in the same initial encrypted frame, making the size of the first packet variable. Before the first packet only had the SOCKS address, with a fixed size, and that was a giveaway.

The censors used to block Shadowsocks, but Shadowsocks has evolved, and in 2021, it was ahead again in the cat and mouse game.

In 2022 China started blocking seemingly random traffic ([report](https://www.opentech.fund/news/exposing-the-great-firewalls-dynamic-blocking-of-fully-encrypted-traffic/)). While there is no evidence they could detect Shadowsocks, the protocol ended up blocked.

As a reponse, we [added a feature to the Outline Client](https://github.com/OutlineFoundation/outline-apps/pull/1454) that allows service managers to specify a **[connection prefix disguise](https://www.reddit.com/r/outlinevpn/wiki/index/prefixing/)** to be used in the Shadowsocks initialization, which can be used to bypass the blocking in China by making it look like a protocol that is allowed.

Shadowsocks remains our protocol of choice because it's simple, well understood and very performant. Furthermore, it has an enthusiastic community of very smart people behind it.
