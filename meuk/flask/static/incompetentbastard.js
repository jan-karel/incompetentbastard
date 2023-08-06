$(".modalweergeven").click(function(){
var loc = $(this).attr('data-rel');
var titel = $(this).attr('data-title');
$(".mijn-tekst").load(loc);
$(".grotemodalweergeven").modal()
});