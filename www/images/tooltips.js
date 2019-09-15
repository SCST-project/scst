var d = document;
var offsetfromcursorY=15 // y offset of tooltip
var ie=d.all && !window.opera;
var ns6=d.getElementById && !d.all;
var tipobj,op;
		
function tooltip(el,txt) {
	tipobj=d.getElementById('mess');
	tipobj.innerHTML = txt;
	op = 0.1;	
	tipobj.style.opacity = op; 
	tipobj.style.display="block";
	tipobj.style.visibility="visible";

	el.onmousemove=positiontip;
	appear();
}

function hide_info(el) {
	d.getElementById('mess').style.visibility='hidden';
	d.getElementById('mess').style.display='none';
	el.onmousemove='';
}

function ietruebody(){
return (d.compatMode && d.compatMode!="BackCompat")? d.documentElement : d.body
}

function positiontip(e) {
	var curX=(ns6)?e.pageX : event.clientX+ietruebody().scrollLeft;
	var curY=(ns6)?e.pageY : event.clientY+ietruebody().scrollTop;
	var winwidth=ie? ietruebody().clientWidth : window.innerWidth-20
	var winheight=ie? ietruebody().clientHeight : window.innerHeight-20
	
	var rightedge=ie? winwidth-event.clientX : winwidth-e.clientX;
	var bottomedge=ie? winheight-event.clientY-offsetfromcursorY : winheight-e.clientY-offsetfromcursorY;

	if (rightedge < tipobj.offsetWidth)	tipobj.style.left=curX-tipobj.offsetWidth+"px";
	else tipobj.style.left=curX+"px";

	if (bottomedge < tipobj.offsetHeight) tipobj.style.top=curY-tipobj.offsetHeight-offsetfromcursorY+"px"
	else tipobj.style.top=curY+offsetfromcursorY+"px";
}

function appear() {	
	if(op < 0.9) {
		op += 0.07;
		tipobj.style.opacity = op;
		tipobj.style.filter = 'alpha(opacity='+op*100+')';
		t = setTimeout('appear()', 30);
	}
}
