// Set 1 - Challenge 2 - Fixed XOR
g=(h,a)=>h.replace(/../g,(c,i)=>('0x'+c^'0x'+a[i]+a[i+1]).toString(16))
console.log(g('1c0111001f010100061a024b53535009181c','686974207468652062756c6c277320657965')
            === '746865206b696420646f6e277420706c6179');