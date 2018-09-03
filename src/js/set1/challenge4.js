// Set 1 - Challenge 4 - Detect single-character XOR
findXorAndPrintStr=(str) => {
    s=str.match(/.{2}/g).map(c=>+`0x${c}`);
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

findInLines=(lines)=>{
    lines=lines.split('\n');
	
	return lines.map((s,i) =>{o=findXorAndPrintStr(s),o.i=i;return o}).reduce((v1,v2) => v1.bestScore>v2.bestScore?v1:v2);
};

findInLines(lines) // where lines is the direct file's contents