"""Change the password on already-built dashboard pages — no Excel rebuild needed.

Usage:
    python change_password.py <old-password> <new-password> [files...]

Each page is re-keyed only if it actually opens with <old-password>, so this is
safe to run across a folder holding pages with different passwords: give an
analyst's old/new pair and only that analyst's page is touched; give the manager
pair and only the shared manager pages (index/isolved/team) are touched.

Remember to update the matching entry in dashboard_password.txt or
analyst_passwords.json afterwards, so the next full rebuild uses the new value.
"""
import io, os, re, sys, json

from build_dashboard import decrypt_payload, wrap_encrypted

PAYLOAD = re.compile(r'<script id="pw-payload" type="application/json">(.*?)</script>', re.S)
TITLE = re.compile(r"<title>(.*?)</title>", re.S)


def main():
    args = sys.argv[1:]
    if len(args) < 2:
        sys.exit(__doc__)
    old, new = args[0], args[1]
    if not new:
        sys.exit("The new password must not be empty.")
    files = args[2:] or sorted(
        f for f in os.listdir(".") if f.lower().endswith(".html"))

    changed = skipped = 0
    for fn in files:
        try:
            with io.open(fn, "r", encoding="utf-8") as f:
                html = f.read()
        except OSError as e:
            print(f"  {fn}: cannot read ({e})"); continue
        m = PAYLOAD.search(html)
        if not m:
            print(f"  {fn}: not an encrypted page, skipped"); skipped += 1; continue
        try:
            plain = decrypt_payload(json.loads(m.group(1)), old)
        except ValueError:
            print(f"  {fn}: old password does not open this page, skipped"); skipped += 1; continue
        t = TITLE.search(html)
        title = t.group(1) if t else "Dashboard"
        with io.open(fn, "w", encoding="utf-8") as f:
            f.write(wrap_encrypted(plain, title, new))
        print(f"  {fn}: re-encrypted with the new password")
        changed += 1

    print(f"\n{changed} page(s) re-keyed, {skipped} skipped.")
    if changed:
        print("Now update dashboard_password.txt / analyst_passwords.json to match.")


if __name__ == "__main__":
    main()
