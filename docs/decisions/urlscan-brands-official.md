# urlscan_brands official set: names added after collection had started

The official set in `watch_urlscan_brands.py` keeps a brand's own registered domains out of the
candidate stream. A name joins it only on evidence the page's operator does not control: a
registry or registrar record whose name servers match live DNS (`whois_vn.py`, ledger under
`data/interim/`, not exported), plus a dated decision by the author.

| Added | Name | Evidence | Already reported? |
| --- | --- | --- | --- |
| 2026-10-02 | `bidvinfo.com.vn` | Registrant: Ngân hàng TMCP Đầu tư và Phát triển Việt Nam (the same registrant as `bidv.com.vn`); registered 2025-09-18 at iNET; NS match. The author identified it as BIDV's news portal. | Yes: reported 2026-10-02 01:00 (+07) with brand token `bidv` |
| 2026-10-02 | `vnptvas.vn` | Registrant: Tập đoàn Bưu chính Viễn thông Việt Nam (the same as `vnpt.vn`); registered 2018-04-24 at Mat Bao; record lists `matbao.vn` NS, live DNS `matbao.com` (one provider). `media-vnpt.vnptvas.vn` resolves to 123.31.36.41 on VNPT's own network (AS135905) and served nginx's default page. | Yes: `media-vnpt.vnptvas.vn`, 2026-10-02 01:00 (+07), token `vnpt` |

A brand-owned name seen only by the CT watcher goes in `CT_BRAND_OWNED` instead
(`ct-brands-brand-owned.md`), never in both: the CT watcher reads the union of the two sets.

What a late addition does to rows already written is recorded in each study's registration
(subdomain-evasion and cloaking deviation records of 2026-10-02), not here.
