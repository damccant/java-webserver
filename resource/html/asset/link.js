function load()
{
	javascriptwarn = document.getElementById("javascript-warning");
	if(javascriptwarn != null)
		javascriptwarn.remove();
	num = 0;
	if(typeof(load_stage2) == typeof(Function))
		load_stage2();
	fetch("/asset/link.txt").then((response) => {
		response.text().then((data) => {
			values = data.split("\n");
			logo = document.getElementById("cse412-logo");
			logo.onclick = function () {
				if (num > 3)
				{
					newlink = values[Math.floor(Math.random() * values.length)];
					logo.href = newlink.substr(0, newlink.indexOf(";"));
				}
				num++;
			}
		})
	});
}