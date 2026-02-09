export const Dimperpreter = class {
	//symbols:
	// , next arguments
	// ; end arguemtns
	// @ escape/skip
	
	constructor(scode){
		this.code = scode;
		this.i=0;
	}
	
	Next(){
		var temp="";
		var param="";
		let params=[];
		while(this.i < this.code.length){
			temp=this.code.substring(this.i,this.i+1);
			if(temp=="@") { this.i++; param+=this.code.substring(this.i,this.i+1); }
			else if(temp==",") { params.push(param); param=""; }
			else if(temp==";") { params.push(param); this.i++; break; }
			else param+=temp;
			this.i++;
		}
		return params;
	}

	LeftRawData() {return this.code.substring(this.i,this.code.length);}
}

export const DimProtect = str => {
	str=str.replaceAll('@','@@');
	str=str.replaceAll(',','@,');
	str=str.replaceAll(';','@;');
	return str;
}