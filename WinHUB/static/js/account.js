(() => {
 const form=document.getElementById('passwordForm'),result=document.getElementById('passwordResult');
 form.addEventListener('submit',async event=>{
  event.preventDefault();const button=form.querySelector('button');result.textContent='';
  const data=Object.fromEntries(new FormData(form));
  if(data.new_password!==data.confirm_password){result.dataset.state='error';result.textContent='New passwords do not match.';return;}
  button.disabled=true;
  try{const response=await fetch('/api/auth/change-password',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':document.querySelector('meta[name="csrf-token"]')?.content||''},body:JSON.stringify(data)});
   const body=await response.json();if(!response.ok)throw new Error(body.message||'Unable to change password.');
   form.reset();result.dataset.state='success';result.textContent=body.message;
   // Refresh the rotated CSRF token without resubmitting any password fields.
   button.hidden=true;const link=document.createElement('a');link.href='/account';link.textContent='Continue';result.append(document.createTextNode(' '),link);
  }catch(error){result.dataset.state='error';result.textContent=error.message;}finally{button.disabled=false;}
 });
})();
