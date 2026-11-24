import subprocess, re
cmd = [r"C:\Program Files\Google\Chrome\Application\chrome.exe", "--headless", "--dump-dom", r"d:\Sem Docs\sem 7 docs\Project\testbed\scratch\guide_temp.html"]
res = subprocess.run(cmd, capture_output=True, text=True)
viewboxes = re.findall(r'viewBox="([^"]+)"', res.stdout)
for i, vb in enumerate(viewboxes):
    print(f"SVG {i+1} viewBox: {vb}")
