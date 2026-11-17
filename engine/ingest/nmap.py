"""Parse nmap XML output → assets and facts."""
from __future__ import annotations
import xml.etree.ElementTree as ET
from .models import Asset, IngestFact, IngestResult

# ARTEX-port: nmap XML ingestion (mirrors db.ingest_scan_output nmap path)


def parse_nmap_xml(xml_content: str, target: str = "") -> IngestResult:
    assets: list[Asset] = []
    facts: list[IngestFact] = []
    errors: list[str] = []

    try:
        root = ET.fromstring(xml_content.strip())
    except ET.ParseError as e:
        return IngestResult(assets=[], facts=[], source_tool="nmap", target=target,
                            errors=[f"nmap XML parse error: {e}"])

    for host in root.findall("host"):
        if host.find("status") is not None and host.find("status").get("state") != "up":
            continue

        ip = ""
        hostnames: list[str] = []

        for addr in host.findall("address"):
            addrtype = addr.get("addrtype", "")
            addrval = addr.get("addr", "")
            if addrtype in ("ipv4", "ipv6") and addrval:
                ip = addrval
                assets.append(Asset(kind="ip", value=ip))

        for hn_elem in host.findall("hostnames/hostname"):
            name = hn_elem.get("name", "")
            if name:
                hostnames.append(name)
                assets.append(Asset(kind="domain", value=name))
                if ip:
                    facts.append(IngestFact(subject=name, predicate="resolves_to", object=ip))

        ports_elem = host.find("ports")
        if ports_elem is None or not ip:
            continue

        for port_elem in ports_elem.findall("port"):
            state_elem = port_elem.find("state")
            if state_elem is None or state_elem.get("state") != "open":
                continue

            portid = port_elem.get("portid", "")
            proto = port_elem.get("protocol", "tcp")
            port_key = f"{ip}:{portid}/{proto}"
            assets.append(Asset(kind="port", value=port_key,
                                attrs={"protocol": proto, "portid": portid}))
            facts.append(IngestFact(subject=ip, predicate="has_open_port", object=portid,
                                    raw={"protocol": proto}))

            svc = port_elem.find("service")
            if svc is not None:
                svc_name = svc.get("name", "")
                product = svc.get("product", "")
                version = svc.get("version", "")
                svc_label = " ".join(filter(None, [svc_name, product, version]))
                if svc_name:
                    facts.append(IngestFact(subject=port_key, predicate="runs_service",
                                            object=svc_label or svc_name,
                                            raw={"name": svc_name, "product": product,
                                                 "version": version}))

            # CVEs from vulners/vulscan scripts
            for script in port_elem.findall("script"):
                script_id = script.get("id", "")
                if script_id not in ("vulners", "vulscan"):
                    continue
                output = script.get("output", "")
                for token in output.split():
                    token = token.strip(",()")
                    if token.upper().startswith("CVE-"):
                        facts.append(IngestFact(
                            subject=port_key, predicate="has_cve", object=token.upper(),
                            raw={"script": script_id},
                        ))

    return IngestResult(assets=assets, facts=facts, source_tool="nmap",
                        target=target, errors=errors)
