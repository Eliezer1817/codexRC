"""
codexRC - CVE Matcher Module
Correlates detected technologies/versions with known CVEs.
Uses the public Circ.lu / NVD-style search via CIRCL CVE Search API (no key required for basic use).
Also supports simple local matching and GitHub security advisory hints.
"""

from typing import List, Dict, Any, Optional
import httpx
import re
from datetime import datetime


class CVEMatcher:
    def __init__(self, timeout: float = 20.0):
        self.timeout = timeout
        self.client = httpx.Client(timeout=timeout, follow_redirects=True)
        # CIRCL CVE Search (public)
        self.circl_base = "https://cve.circl.lu/api"

    def search_cve_by_keyword(self, keyword: str, limit: int = 15) -> List[Dict[str, Any]]:
        """
        Search CVEs by product/vendor keyword.
        Example: keyword="wordpress", "apache", "nginx 1.18", "jquery 3.5"
        """
        try:
            # CIRCL search endpoint
            url = f"{self.circl_base}/search/{keyword}"
            r = self.client.get(url)
            if r.status_code != 200:
                # Fallback: try /cvefor or simple browse
                return self._fallback_search(keyword, limit)

            data = r.json()
            results = []

            # CIRCL can return different shapes
            items = []
            if isinstance(data, dict):
                items = data.get("results", data.get("data", []))
                if not items and "id" in data:
                    items = [data]
            elif isinstance(data, list):
                items = data

            for item in items[:limit]:
                cve_id = item.get("id”) or item.get("cve") or item.get("CVE") or ""
                summary = item.get("summary") or item.get("description") or item.get("summary_text") or ""
                cvss = item.get("cvss") or item.get("cvss3") or item.get("cvss_score")
                published = item.get("Published") or item.get("published") or item.get("date")

                results.append({
                    "cve_id": cve_id,
                    "summary": summary[:400] if summary else "",
                    "cvss": cvss,
                    "published": published,
                    "source": "circl",
                    "raw": {k: item.get(k) for k in ("id", "summary", "cvss", "Published") if k in item},
                })

            return results
        except Exception as e:
            return [{"error": str(e), "keyword": keyword}]

    def _fallback_search(self, keyword: str, limit: int) -> List[Dict[str, Any]]:
        """Very basic fallback using CIRCL browse or empty."""
        try:
            # Try vendor/product style if possible
            parts = keyword.lower().split()
            if len(parts) >= 2:
                vendor, product = parts[0], parts[1]
                url = f"{self.circl_base}/search/{vendor}/{product}"
                r = self.client.get(url)
                if r.status_code == 200:
                    data = r.json()
                    items = data if isinstance(data, list) else data.get("results", [])
                    return [
                        {
                            "cve_id": i.get("id", ""),
                            "summary": (i.get("summary") or "")[:400],
                            "cvss": i.get("cvss"),
                            "published": i.get("Published"),
                            "source": "circl-fallback",
                        }
                        for i in items[:limit]
                    ]
        except Exception:
            pass
        return []

    def match_technologies(self, technologies: List[Dict[str, Any]], max_per_tech: int = 8) -> Dict[str, Any]:
        """
        technologies example:
        [
          {"name": "WordPress", "version": "5.8.1"},
          {"name": "jQuery", "version": "3.5.0"},
          {"name": "nginx", "version": None}
        ]
        """
        report = {
            "scanned_at": datetime.utcnow().isoformat() + "Z",
            "technologies": [],
            "total_cves_found": 0,
            "high_priority": [],
        }

        for tech in technologies:
            name = tech.get("name") or tech.get("technology") or ""
            version = tech.get("version")
            query = f"{name} {version}".strip() if version else name

            if not query:
                continue

            cves = self.search_cve_by_keyword(query, limit=max_per_tech)

            # Simple prioritization by CVSS if available
            high = []
            for c in cves:
                if c.get("error"):
                    continue
                score = c.get("cvss")
                try:
                    if score is not None and float(score) >= 7.0:
                        high.append(c)
                except (TypeError, ValueError):
                    pass

            entry = {
                "technology": name,
                "version": version,
                "query": query,
                "cves": cves,
                "high_cvss_count": len(high),
            }
            report["technologies"].append(entry)
            report["total_cves_found"] += len([c for c in cves if not c.get("error")])
            report["high_priority"].extend(high)

        return report

    def quick_check(self, product: str, version: Optional[str] = None) -> List[Dict[str, Any]]:
        """Convenience helper."""
        q = f"{product} {version}".strip() if version else product
        return self.search_cve_by_keyword(q)

    def close(self):
        self.client.close()
