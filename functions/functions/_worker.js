import { Hono } from 'hono'
import { cors } from 'hono/cors'

const app = new Hono()

app.use('/api/*', cors({
  origin: '*',
  allowMethods: ['GET','POST','PUT','PATCH','DELETE','OPTIONS'],
  allowHeaders: ['Content-Type','Authorization','X-Admin-Password'],
}))

function json(data, status=200){
  return new Response(JSON.stringify(data),{status,headers:{'Content-Type':'application/json'}})
}
function genUUID(){ return crypto.randomUUID() }

async function sha256(text){
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text))
  return Array.from(new Uint8Array(buf)).map(b=>b.toString(16).padStart(2,'0')).join('')
}

async function signJWT(payload, secret){
  const h = btoa(JSON.stringify({alg:'HS256',typ:'JWT'})).replace(/=/g,'').replace(/\+/g,'-').replace(/\//g,'_')
  const b = btoa(JSON.stringify(payload)).replace(/=/g,'').replace(/\+/g,'-').replace(/\//g,'_')
  const key = await crypto.subtle.importKey('raw',new TextEncoder().encode(secret),{name:'HMAC',hash:'SHA-256'},false,['sign'])
  const sig = await crypto.subtle.sign('HMAC',key,new TextEncoder().encode(`${h}.${b}`))
  const s = btoa(String.fromCharCode(...new Uint8Array(sig))).replace(/=/g,'').replace(/\+/g,'-').replace(/\//g,'_')
  return `${h}.${b}.${s}`
}

async function verifyJWT(token, secret){
  try{
    const [h,b,s] = token.split('.')
    const key = await crypto.subtle.importKey('raw',new TextEncoder().encode(secret),{name:'HMAC',hash:'SHA-256'},false,['verify'])
    const sigB = Uint8Array.from(atob(s.replace(/-/g,'+').replace(/_/g,'/')),c=>c.charCodeAt(0))
    const ok = await crypto.subtle.verify('HMAC',key,sigB,new TextEncoder().encode(`${h}.${b}`))
    if(!ok) return null
    const p = JSON.parse(atob(b.replace(/-/g,'+').replace(/_/g,'/')))
    if(p.exp && Date.now()/1000 > p.exp) return null
    return p
  }catch{return null}
}

async function getUser(req, secret){
  const auth = req.headers.get('Authorization')||''
  if(!auth.startsWith('Bearer ')) return null
  return verifyJWT(auth.slice(7), secret)
}

async function isAdmin(req, hash){
  const pwd = req.headers.get('X-Admin-Password')||''
  if(!pwd) return false
  return await sha256(pwd) === hash || pwd === hash
}

const ADMIN_HASH = '240be518fabd2724ddb6f04eeb1da5967448d7e831c08c8fa822809f74c720a9'

// AUTH
app.post('/api/auth/register', async(c)=>{
  const {name,email,password} = await c.req.json().catch(()=>({}))
  if(!name||!email||!password) return json({error:'Campos obrigatórios'},400)
  if(password.length<6) return json({error:'Senha min 6 caracteres'},400)
  const exists = await c.env.DB.prepare('SELECT id FROM users WHERE email=?').bind(email.toLowerCase()).first()
  if(exists) return json({error:'Email já cadastrado'},409)
  const id=genUUID(), hash=await sha256(password)
  await c.env.DB.prepare('INSERT INTO users(id,name,email,password_hash) VALUES(?,?,?,?)').bind(id,name.trim(),email.toLowerCase(),hash).run()
  const token = await signJWT({id,name,email:email.toLowerCase(),exp:Math.floor(Date.now()/1000)+604800}, c.env.JWT_SECRET||'dev-secret')
  return json({token,user:{id,name,email:email.toLowerCase()}},201)
})

app.post('/api/auth/login', async(c)=>{
  const {email,password} = await c.req.json().catch(()=>({}))
  if(!email||!password) return json({error:'Campos obrigatórios'},400)
  const user = await c.env.DB.prepare('SELECT * FROM users WHERE email=?').bind(email.toLowerCase()).first()
  if(!user) return json({error:'Email ou senha incorretos'},401)
  if(await sha256(password) !== user.password_hash) return json({error:'Email ou senha incorretos'},401)
  const token = await signJWT({id:user.id,name:user.name,email:user.email,exp:Math.floor(Date.now()/1000)+604800}, c.env.JWT_SECRET||'dev-secret')
  return json({token,user:{id:user.id,name:user.name,email:user.email}})
})

app.get('/api/auth/me', async(c)=>{
  const user = await getUser(c.req.raw, c.env.JWT_SECRET||'dev-secret')
  if(!user) return json({error:'Não autenticado'},401)
  return json({user})
})

// CAMPANHAS
app.get('/api/campaigns', async(c)=>{
  const status=c.req.query('status')||'active'
  const category=c.req.query('category')||''
  const search=c.req.query('search')||''
  const page=Math.max(1,parseInt(c.req.query('page')||'1'))
  const limit=Math.min(100,parseInt(c.req.query('limit')||'20'))
  const offset=(page-1)*limit
  let q='SELECT * FROM campaigns WHERE 1=1', p=[]
  if(status!=='all'){q+=' AND status=?';p.push(status)}
  if(category){q+=' AND category=?';p.push(category)}
  if(search){q+=' AND (title LIKE ? OR description LIKE ?)';p.push(`%${search}%`,`%${search}%`)}
  const cp=[...p]
  q+=' ORDER BY created_at DESC LIMIT ? OFFSET ?';p.push(limit,offset)
  let cq='SELECT COUNT(*) as total FROM campaigns WHERE 1=1'
  if(status!=='all') cq+=' AND status=?'
  if(category) cq+=' AND category=?'
  if(search) cq+=' AND (title LIKE ? OR description LIKE ?)'
  const [rows,cnt]=await Promise.all([c.env.DB.prepare(q).bind(...p).all(),c.env.DB.prepare(cq).bind(...cp).first()])
  return json({data:rows.results,total:cnt?.total||0,page,limit})
})

app.get('/api/campaigns/:id', async(c)=>{
  const r=await c.env.DB.prepare('SELECT * FROM campaigns WHERE id=?').bind(c.req.param('id')).first()
  return r ? json(r) : json({error:'Não encontrado'},404)
})

app.get('/api/my-campaigns', async(c)=>{
  const user=await getUser(c.req.raw,c.env.JWT_SECRET||'dev-secret')
  if(!user) return json({error:'Não autenticado'},401)
  const rows=await c.env.DB.prepare('SELECT * FROM campaigns WHERE user_id=? ORDER BY created_at DESC').bind(user.id).all()
  return json(rows.results)
})

app.post('/api/campaigns', async(c)=>{
  const user=await getUser(c.req.raw,c.env.JWT_SECRET||'dev-secret')
  if(!user) return json({error:'Não autenticado'},401)
  const {title,description,goal_amount,pix_key,pix_key_type,category,image_url}=await c.req.json().catch(()=>({}))
  if(!title||!description||!goal_amount||!pix_key||!pix_key_type||!category) return json({error:'Campos obrigatórios'},400)
  const id=genUUID()
  await c.env.DB.prepare(`INSERT INTO campaigns(id,title,description,goal_amount,current_amount,pix_key,pix_key_type,category,image_url,author_name,author_email,user_id,status) VALUES(?,?,?,?,0,?,?,?,?,?,?,'pending')`).bind(id,String(title).trim(),String(description).trim(),Number(goal_amount),String(pix_key).trim(),String(pix_key_type),String(category),String(image_url||''),String(user.name||''),String(user.email||''),String(user.id)).run()
  return json(await c.env.DB.prepare('SELECT * FROM campaigns WHERE id=?').bind(id).first(),201)
})

// DOAÇÕES
app.get('/api/campaigns/:id/donations', async(c)=>{
  const rows=await c.env.DB.prepare(`SELECT * FROM donations WHERE campaign_id=? AND payment_status='paid' ORDER BY created_at DESC LIMIT 50`).bind(c.req.param('id')).all()
  return json(rows.results)
})

app.post('/api/donations', async(c)=>{
  const {campaign_id,donor_name,amount,message,is_anonymous}=await c.req.json().catch(()=>({}))
  if(!campaign_id||!amount||Number(amount)<1) return json({error:'Dados inválidos'},400)
  const camp=await c.env.DB.prepare(`SELECT * FROM campaigns WHERE id=? AND status='active'`).bind(String(campaign_id)).first()
  if(!camp) return json({error:'Campanha não encontrada'},404)
  const id=genUUID()
  await c.env.DB.prepare(`INSERT INTO donations(id,campaign_id,donor_name,amount,message,is_anonymous,payment_status,pix_code) VALUES(?,?,?,?,?,?,'pending',?)`).bind(id,String(campaign_id),is_anonymous?'':String(donor_name||''),Number(amount),String(message||''),is_anonymous?1:0,String(camp.pix_key||'')).run()
  return json(await c.env.DB.prepare('SELECT * FROM donations WHERE id=?').bind(id).first(),201)
})

app.patch('/api/donations/:id/confirm', async(c)=>{
  const d=await c.env.DB.prepare('SELECT * FROM donations WHERE id=?').bind(c.req.param('id')).first()
  if(!d) return json({error:'Não encontrado'},404)
  if(d.payment_status==='paid') return json({message:'Já confirmado'})
  await c.env.DB.prepare(`UPDATE donations SET payment_status='paid' WHERE id=?`).bind(d.id).run()
  await c.env.DB.prepare(`UPDATE campaigns SET current_amount=current_amount+?,updated_at=datetime('now') WHERE id=?`).bind(d.amount,d.campaign_id).run()
  return json({success:true})
})

// PAGAMENTOS PIX
app.post('/api/payments/create', async(c)=>{
  const {campaign_id,amount,donor_name,donor_email,donor_message,is_anonymous}=await c.req.json().catch(()=>({}))
  if(!campaign_id||!amount||Number(amount)<1) return json({error:'Dados inválidos'},400)
  const camp=await c.env.DB.prepare(`SELECT * FROM campaigns WHERE id=? AND status='active'`).bind(String(campaign_id)).first()
  if(!camp) return json({error:'Campanha não encontrada'},404)
  const mpToken=c.env.MERCADOPAGO_ACCESS_TOKEN
  if(!mpToken){
    const id=genUUID()
    await c.env.DB.prepare(`INSERT INTO donations(id,campaign_id,donor_name,amount,message,is_anonymous,payment_status,pix_code) VALUES(?,?,?,?,?,?,'pending',?)`).bind(id,String(campaign_id),is_anonymous?'':String(donor_name||''),Number(amount),String(donor_message||''),is_anonymous?1:0,String(camp.pix_key||'')).run()
    return json({success:true,method:'manual',donation_id:id,pix_key:camp.pix_key,pix_key_type:camp.pix_key_type,amount})
  }
  try{
    const txid=`vakinha-${Date.now()}-${Math.random().toString(36).slice(2,8)}`
    const mpRes=await fetch('https://api.mercadopago.com/v1/payments',{method:'POST',headers:{'Authorization':`Bearer ${mpToken}`,'Content-Type':'application/json','X-Idempotency-Key':txid},body:JSON.stringify({transaction_amount:parseFloat(String(amount)),description:`Doação: ${String(camp.title||'').slice(0,100)}`,payment_method_id:'pix',payer:{email:donor_email||'doador@vakinha.com',first_name:is_anonymous?'Anônimo':String(donor_name||'').split(' ')[0]||'Doador',last_name:is_anonymous?'':String(donor_name||'').split(' ').slice(1).join(' ')||''}})})
    const mpData=await mpRes.json()
    const txData=mpData?.point_of_interaction?.transaction_data
    if(!mpRes.ok||!txData) throw new Error(mpData.message||'Erro Mercado Pago')
    const pixCode=String(txData.qr_code||''), pixQR=String(txData.qr_code_base64||'')
    const pid=genUUID()
    await c.env.DB.prepare(`INSERT INTO payments(id,txid,campaign_id,amount,donor_name,donor_email,donor_message,is_anonymous,pix_code,pix_qrcode_base64,status,mp_payment_id) VALUES(?,?,?,?,?,?,?,?,?,?,'pending',?)`).bind(pid,txid,String(campaign_id),Number(amount),is_anonymous?'':String(donor_name||''),String(donor_email||''),String(donor_message||''),is_anonymous?1:0,pixCode,pixQR,String(mpData.id||'')).run()
    return json({success:true,method:'mercadopago',payment_id:pid,txid,amount,pix_code:pixCode,pix_qrcode_base64:pixQR,mp_payment_id:mpData.id})
  }catch(e){return json({error:`Erro PIX: ${e.message}`},500)}
})

app.get('/api/payments/:txid/status', async(c)=>{
  const p=await c.env.DB.prepare('SELECT * FROM payments WHERE txid=?').bind(c.req.param('txid')).first()
  return p ? json({status:p.status,paid_at:p.paid_at}) : json({error:'Não encontrado'},404)
})

app.post('/api/webhook/mercadopago', async(c)=>{
  const body=await c.req.json().catch(()=>({}))
  const mpToken=c.env.MERCADOPAGO_ACCESS_TOKEN
  if(body.type==='payment'&&body.data&&mpToken){
    const mpId=String(body.data.id||'')
    try{
      const res=await fetch(`https://api.mercadopago.com/v1/payments/${mpId}`,{headers:{'Authorization':`Bearer ${mpToken}`}})
      const pay=await res.json()
      if(pay.status==='approved'){
        const local=await c.env.DB.prepare('SELECT * FROM payments WHERE mp_payment_id=?').bind(mpId).first()
        if(local&&local.status!=='paid'){
          await c.env.DB.prepare(`UPDATE payments SET status='paid',paid_at=datetime('now') WHERE id=?`).bind(local.id).run()
          const did=genUUID()
          await c.env.DB.prepare(`INSERT INTO donations(id,campaign_id,donor_name,donor_email,amount,message,is_anonymous,payment_status,pix_code) VALUES(?,?,?,?,?,?,?,'paid',?)`).bind(did,local.campaign_id,local.donor_name,local.donor_email,local.amount,local.donor_message,local.is_anonymous,local.pix_code).run()
          await c.env.DB.prepare(`UPDATE campaigns SET current_amount=current_amount+?,updated_at=datetime('now') WHERE id=?`).bind(local.amount,local.campaign_id).run()
        }
      }
    }catch(e){console.error(e)}
  }
  return new Response('OK',{status:200})
})

// ADMIN
app.post('/api/admin/login', async(c)=>{
  const {password}=await c.req.json().catch(()=>({}))
  if(!password) return json({error:'Senha obrigatória'},400)
  const hash=c.env.ADMIN_PASSWORD||ADMIN_HASH
  if(await sha256(password)!==hash&&password!==hash) return json({error:'Senha incorreta'},401)
  return json({success:true})
})

app.get('/api/admin/stats', async(c)=>{
  if(!await isAdmin(c.req.raw,c.env.ADMIN_PASSWORD||ADMIN_HASH)) return json({error:'Não autorizado'},401)
  const [u,camps,d]=await Promise.all([
    c.env.DB.prepare('SELECT COUNT(*) as total FROM users').first(),
    c.env.DB.prepare('SELECT status,COUNT(*) as cnt FROM campaigns GROUP BY status').all(),
    c.env.DB.prepare(`SELECT COUNT(*) as total,SUM(amount) as sum FROM donations WHERE payment_status='paid'`).first()
  ])
  const cs={}; for(const r of (camps.results||[])) cs[r.status]=r.cnt
  return json({users:u?.total||0,campaigns:{total:Object.values(cs).reduce((a,b)=>a+b,0),active:cs.active||0,pending:cs.pending||0,rejected:cs.rejected||0,completed:cs.completed||0},donations:{total:d?.total||0,sum:d?.sum||0}})
})

app.get('/api/admin/campaigns', async(c)=>{
  if(!await isAdmin(c.req.raw,c.env.ADMIN_PASSWORD||ADMIN_HASH)) return json({error:'Não autorizado'},401)
  const status=c.req.query('status')||'all'
  let q='SELECT * FROM campaigns', p=[]
  if(status!=='all'){q+=' WHERE status=?';p.push(status)}
  q+=' ORDER BY created_at DESC'
  return json((await c.env.DB.prepare(q).bind(...p).all()).results)
})

app.get('/api/admin/donations', async(c)=>{
  if(!await isAdmin(c.req.raw,c.env.ADMIN_PASSWORD||ADMIN_HASH)) return json({error:'Não autorizado'},401)
  return json((await c.env.DB.prepare('SELECT * FROM donations ORDER BY created_at DESC LIMIT 200').all()).results)
})

app.get('/api/admin/users', async(c)=>{
  if(!await isAdmin(c.req.raw,c.env.ADMIN_PASSWORD||ADMIN_HASH)) return json({error:'Não autorizado'},401)
  return json((await c.env.DB.prepare('SELECT id,name,email,created_at FROM users ORDER BY created_at DESC').all()).results)
})

app.put('/api/admin/campaigns/:id/approve', async(c)=>{
  if(!await isAdmin(c.req.raw,c.env.ADMIN_PASSWORD||ADMIN_HASH)) return json({error:'Não autorizado'},401)
  await c.env.DB.prepare(`UPDATE campaigns SET status='active',approval_date=datetime('now'),updated_at=datetime('now') WHERE id=?`).bind(c.req.param('id')).run()
  return json({success:true})
})

app.put('/api/admin/campaigns/:id/reject', async(c)=>{
  if(!await isAdmin(c.req.raw,c.env.ADMIN_PASSWORD||ADMIN_HASH)) return json({error:'Não autorizado'},401)
  const {notes}=await c.req.json().catch(()=>({}))
  await c.env.DB.prepare(`UPDATE campaigns SET status='rejected',admin_notes=?,updated_at=datetime('now') WHERE id=?`).bind(notes||'',c.req.param('id')).run()
  return json({success:true})
})

app.put('/api/admin/campaigns/:id/complete', async(c)=>{
  if(!await isAdmin(c.req.raw,c.env.ADMIN_PASSWORD||ADMIN_HASH)) return json({error:'Não autorizado'},401)
  await c.env.DB.prepare(`UPDATE campaigns SET status='completed',updated_at=datetime('now') WHERE id=?`).bind(c.req.param('id')).run()
  return json({success:true})
})

app.delete('/api/admin/campaigns/:id', async(c)=>{
  if(!await isAdmin(c.req.raw,c.env.ADMIN_PASSWORD||ADMIN_HASH)) return json({error:'Não autorizado'},401)
  const force=c.req.query('force')==='true', id=c.req.param('id')
  const cnt=await c.env.DB.prepare('SELECT COUNT(*) as cnt FROM donations WHERE campaign_id=?').bind(id).first()
  if((cnt?.cnt||0)>0&&!force) return json({error:'Possui doações. Use ?force=true',can_force:true,donations_count:cnt?.cnt},409)
  if(force){
    await c.env.DB.prepare('DELETE FROM donations WHERE campaign_id=?').bind(id).run()
    await c.env.DB.prepare('DELETE FROM payments WHERE campaign_id=?').bind(id).run()
  }
  await c.env.DB.prepare('DELETE FROM campaigns WHERE id=?').bind(id).run()
  return json({success:true})
})

app.get('/api/health',(c)=>c.json({status:'ok',version:'4.0',ts:new Date().toISOString()}))

export default {
  async fetch(request, env, ctx){ return app.fetch(request, env, ctx) }
}
</parameter>
<parameter name="file_path">functions/_worker.js</parameter>
</invoke>
