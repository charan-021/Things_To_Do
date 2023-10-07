function unlock(lock,unlock,pass){
  document.getElementById(lock).style.zIndex = 1;
  document.getElementById(unlock).style.zIndex = -1;
  var pd=document.getElementById(pass);
  if(pd.type === "text"){
    pd.type = "password";
  }
}
function lock(lock,unlock,pass){
  document.getElementById(lock).style.zIndex = -1;
  document.getElementById(unlock).style.zIndex = 1;
  var pd=document.getElementById(pass);
  if(pd.type === "password"){
    pd.type = 'text';
  }
}