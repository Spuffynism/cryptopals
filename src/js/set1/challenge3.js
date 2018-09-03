// Set 1 - Challenge 3 - Single-byte XOR cipher
findXorAndPrintStr=(str) => {
    s=str.match(/../g).map(c=>+`0x${c}`);
    a='abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ\'" '
    bestScore=-1,bestChar=null;
    for(i=1;i<=255;i++) {
        currentScore=0
        xoredSorted=s.map(c=>c^i);
        for(j=0;j<a.length;j++){
            currentScore+=xoredSorted.filter(x => x === a.charCodeAt(j)).length;
        }

        if (currentScore >= bestScore) {
            bestScore = currentScore;
            bestChar=String.fromCharCode(i);
        }
    }

    bestXored=s.map(c=>c^bestChar.charCodeAt()).map(c => String.fromCharCode(c)).join('')
    
	return {bestScore,bestXored,str,bestChar};
};

f=t=>{
for(s=t.match(/../g).map(c=>+`0x${c}`,a='abcdefghijklmnopqrstuvwxyz\'" ',a+=a.toUpperCase()),b=k=0,i=255;i--;){
c=0
x=s.map(c=>c^i)
for(j=a.length;j--;)c+=x.filter(x=>x==a.charCodeAt(j)).length
if(c>=b)b=c,k=String.fromCharCode(i)
}
return{m:s.map(c=>String.fromCharCode(c^k.charCodeAt())).join``,k}
}
console.log(f('1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'))