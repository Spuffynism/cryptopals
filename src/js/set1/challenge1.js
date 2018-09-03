// Set 1 - Challenge 1 - Convert hex to base64
f=h=>btoa(h.replace(/../g,c=>String.fromCharCode('0x'+c)))
console.log(f('49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d') 
            === 'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t');