$(".modalweergeven").click(function(){
var loc = $(this).attr('data-rel');
var title = $(this).attr('data-title');
$('#grotemodal').html('<h4>'+title+'</h4>');
$(".mijn-tekst").load(loc);
$(".grotemodalweergeven").modal()

});


$(".delete_finding").click(function(){
	var loc = $(this).attr('data-rel');
	var div = $(this).attr('data-item');

  let text = "Are you sure?\nEither OK or Cancel.";
  if (confirm(text) == true) {
	$('#'+div).load('/dashboard/findings/delete/'+loc);
}
});