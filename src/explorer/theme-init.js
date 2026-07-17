// Restore theme before first paint to prevent flash
(function(){
  var t=localStorage.getItem('cync-theme');
  if(t){document.documentElement.setAttribute('data-theme',t);
    if(['dark','midnight','forge','vault','mono','contrast'].indexOf(t)!==-1)document.documentElement.classList.add('dark');
  }else{document.documentElement.classList.add('dark');}
})();
