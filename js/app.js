// This front-end is an illustrative simulation, not a real-world threat-intelligence feed.
const svg=d3.select('#world');
const colors={
  'Malicious Traffic':'#ff315b',
  'Suspicious Activity':'#ffb941',
  'Scanning Activity':'#08d7ff',
  'Botnet Activity':'#c05cff'
};
const attackTypes=Object.keys(colors);
const countries=[
 {name:'United States',flag:'🇺🇸',ll:[-98,39]},
 {name:'Russia',flag:'🇷🇺',ll:[90,60]},
 {name:'Brazil',flag:'🇧🇷',ll:[-52,-10]},
 {name:'Vietnam',flag:'🇻🇳',ll:[108,16]},
 {name:'Pakistan',flag:'🇵🇰',ll:[69,30]},
 {name:'Iran',flag:'🇮🇷',ll:[53,32]},
 {name:'Israel',flag:'🇮🇱',ll:[35,31]},
 {name:'India',flag:'🇮🇳',ll:[78,21]},
 {name:'Ukraine',flag:'🇺🇦',ll:[32,49]},
 {name:'Bangladesh',flag:'🇧🇩',ll:[90,24]},
 {name:'China',flag:'🇨🇳',ll:[105,35]},
 {name:'United Kingdom',flag:'🇬🇧',ll:[-2,54]},
 {name:'France',flag:'🇫🇷',ll:[2,46]},
 {name:'Germany',flag:'🇩🇪',ll:[10,51]},
 {name:'Japan',flag:'🇯🇵',ll:[138,36]},
 {name:'South Korea',flag:'🇰🇷',ll:[128,36]},
 {name:'North Korea',flag:'🇰🇵',ll:[127,40]},
 {name:'Australia',flag:'🇦🇺',ll:[133,-25]},
 {name:'Canada',flag:'🇨🇦',ll:[-106,56]},
 {name:'Mexico',flag:'🇲🇽',ll:[-102,23]},
 {name:'Indonesia',flag:'🇮🇩',ll:[118,-2]},
 {name:'Saudi Arabia',flag:'🇸🇦',ll:[45,24]},
 {name:'Turkey',flag:'🇹🇷',ll:[35,39]},
 {name:'Egypt',flag:'🇪🇬',ll:[30,26]},
 {name:'South Africa',flag:'🇿🇦',ll:[24,-29]},
 {name:'Nigeria',flag:'🇳🇬',ll:[8,9]},
 {name:'Italy',flag:'🇮🇹',ll:[12,42]},
 {name:'Spain',flag:'🇪🇸',ll:[-4,40]},
 {name:'Poland',flag:'🇵🇱',ll:[19,52]},
 {name:'Netherlands',flag:'🇳🇱',ll:[5,52]}
];

let W=1200,H=650,projection,path,routeGroup,nodeGroup,routeData=[];
let eventHistory=[],totalAttacks=82461,eventsToday=0,resizeTimer;
const MAX_HISTORY=18;
const pick=(arr)=>arr[Math.floor(Math.random()*arr.length)];
const formatTime=(date)=>date.toLocaleTimeString('en-GB',{hour12:false});
function makeEvent(){
  const sourceIndex=Math.floor(Math.random()*countries.length);
  let targetIndex=Math.floor(Math.random()*(countries.length-1));
  if(targetIndex>=sourceIndex) targetIndex++;
  return {
    id:Date.now()+Math.random(),
    source:sourceIndex,target:targetIndex,type:pick(attackTypes),
    time:new Date(),age:0,
    intensity:.7+Math.random()*.8,
    duration:3400+Math.random()*4200
  };
}
function setup(){
  const el=document.querySelector('.stage');
  W=el.clientWidth;H=el.clientHeight;
  svg.attr('viewBox',`0 0 ${W} ${H}`).attr('preserveAspectRatio','xMidYMid meet');
  svg.selectAll('*').remove();
  projection=d3.geoEquirectangular().fitExtent([[12,12],[W-12,H-12]],{type:'Sphere'});
  path=d3.geoPath(projection);
  svg.append('defs').html(`
    <filter id="glow" x="-150%" y="-150%" width="400%" height="400%">
      <feGaussianBlur stdDeviation="3.2" result="blur"/>
      <feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge>
    </filter>
    <filter id="softGlow" x="-200%" y="-200%" width="500%" height="500%">
      <feGaussianBlur stdDeviation="7" result="blur"/>
      <feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge>
    </filter>
    <radialGradient id="land"><stop stop-color="#0d3454"/><stop offset="1" stop-color="#06172b"/></radialGradient>
  `);
  svg.append('path').datum({type:'Sphere'}).attr('d',path).attr('fill','none').attr('stroke','#174d72').attr('stroke-width',1);
  svg.append('path').datum(d3.geoGraticule().step([15,15])()).attr('d',path).attr('fill','none').attr('stroke','#12314b').attr('stroke-width',.55).attr('opacity',.65);
  routeGroup=svg.append('g').attr('class','active-events');
  nodeGroup=svg.append('g').attr('class','event-lights');
}
function drawMap(world){
  const land=topojson.feature(world,world.objects.land);
  svg.insert('path',':first-child').datum(land).attr('d',path).attr('fill','url(#land)').attr('stroke','#1a628b').attr('stroke-width',.7);
  if(world.objects.countries){
    svg.append('g').attr('class','country-borders')
      .selectAll('path').data(topojson.feature(world,world.objects.countries).features).join('path')
      .attr('d',path).attr('fill','rgba(9,39,63,.20)').attr('stroke','#12486a').attr('stroke-width',.42);
  }
}
function curve(a,b){
  // Build a gently elevated great-circle arc; no pre-drawn dotted paths.
  return d3.geoInterpolate(a,b);
}
function addEventVisual(event){
  const a=countries[event.source].ll,b=countries[event.target].ll;
  const color=colors[event.type],interpolate=curve(a,b);
  const points=d3.range(0,1.001,.012).map(t=>interpolate(t));
  const geo={type:'LineString',coordinates:points};
  const d=path(geo);
  const group=routeGroup.append('g').attr('class','live-route');
  // A faint solid trail fades behind the moving light.
  group.append('path').attr('d',d).attr('fill','none').attr('stroke',color)
    .attr('stroke-width',1.1).attr('stroke-opacity',.2).attr('filter','url(#glow)');
  const start=projection(a),end=projection(b);
  const sourcePulse=nodeGroup.append('circle').attr('cx',start[0]).attr('cy',start[1])
    .attr('r',3).attr('fill',color).attr('filter','url(#glow)').attr('opacity',.95);
  const targetHalo=nodeGroup.append('circle').attr('cx',end[0]).attr('cy',end[1])
    .attr('r',2).attr('fill','none').attr('stroke',color).attr('stroke-width',1.4)
    .attr('filter','url(#glow)').attr('opacity',.85);
  const mover=nodeGroup.append('circle').attr('r',3.2).attr('fill','#fff')
    .attr('stroke',color).attr('stroke-width',2).attr('filter','url(#softGlow)');
  const head=nodeGroup.append('circle').attr('r',7).attr('fill',color).attr('opacity',.12);
  routeData.push({event,group,mover,head,sourcePulse,targetHalo,start,end,duration:event.duration,created:performance.now()});
}
function pruneVisuals(){
  const now=performance.now();
  routeData=routeData.filter(r=>{
    const p=Math.min(1,(now-r.created)/r.duration);
    if(p>=1){
      r.group.remove();r.mover.remove();r.head.remove();r.sourcePulse.remove();r.targetHalo.remove();
      return false;
    }
    return true;
  });
}
function animate(now){
  routeData.forEach(r=>{
    const p=Math.min(1,(now-r.created)/r.duration);
    // Smooth acceleration/deceleration gives the packet a natural light-flight feel.
    const eased=p<.5?2*p*p:1-Math.pow(-2*p+2,2)/2;
    const geo=d3.geoInterpolate(countries[r.event.source].ll,countries[r.event.target].ll);
    const point=projection(geo(eased));
    r.mover.attr('cx',point[0]).attr('cy',point[1]).attr('opacity',p>.94?(1-p)/.06:1);
    r.head.attr('cx',point[0]).attr('cy',point[1]).attr('r',5+Math.sin(now/90)*1.5).attr('opacity',.18*(1-p));
    const pulse=3+((now/240)%1)*7;
    r.targetHalo.attr('r',p>.84?pulse:2.5).attr('opacity',p>.84?Math.max(0,1-(p-.84)/.16):.75);
    r.sourcePulse.attr('r',2.5+Math.sin(now/160)*1.1);
  });
  pruneVisuals();
  requestAnimationFrame(animate);
}
function recordEvent(event){
  eventHistory.unshift(event);
  if(eventHistory.length>MAX_HISTORY)eventHistory.length=MAX_HISTORY;
  eventsToday++;
  totalAttacks+=1;
  renderPanels();renderMetrics();
  addEventVisual(event);
}
function renderPanels(){
  const recent=document.getElementById('recent'),feed=document.getElementById('feed');
  recent.innerHTML='';feed.innerHTML='';
  eventHistory.slice(0,7).forEach((e)=>{
    const a=countries[e.source],b=countries[e.target],age=Math.max(0,Math.floor((Date.now()-e.time.getTime())/1000));
    const row=document.createElement('div');row.className='attack';
    row.innerHTML=`<span class="dot" style="background:${colors[e.type]};color:${colors[e.type]}"></span>
      <div><div class="route"></div><div class="kind"></div></div><span class="age">${age<2?'now':age+'s ago'}</span>`;
    row.querySelector('.route').textContent=`${a.flag} ${a.name} → ${b.name}`;
    row.querySelector('.kind').textContent=e.type;row.querySelector('.kind').style.color=colors[e.type];
    recent.appendChild(row);
  });
  eventHistory.slice(0,7).forEach(e=>{
    const a=countries[e.source],b=countries[e.target],card=document.createElement('div');
    card.className='feedcard';
    const top=document.createElement('div');top.innerHTML=`<small>${formatTime(e.time)}</small>　`;
    const route=document.createElement('b');route.textContent=`${a.flag} ${a.name} → ${b.name}`;
    top.appendChild(route);
    const kind=document.createElement('div');kind.className='feedkind';kind.textContent=e.type;kind.style.color=colors[e.type];
    card.append(top,kind);feed.appendChild(card);
  });
}
function renderMetrics(){
  document.getElementById('total').innerHTML=totalAttacks.toLocaleString()+' <span class="green">↑ LIVE</span>';
  const counts={};eventHistory.forEach(e=>counts[e.type]=(counts[e.type]||0)+1);
  const topType=Object.entries(counts).sort((a,b)=>b[1]-a[1])[0];
  const typeEl=document.querySelector('.metric:nth-child(2) strong');
  const typeSub=document.querySelector('.metric:nth-child(2) .sub');
  if(topType){typeEl.textContent='◉ '+topType[0];typeSub.textContent=`${Math.round(topType[1]/eventHistory.length*100)}% of recent events`;}
  const countryCounts={};eventHistory.forEach(e=>countryCounts[e.source]=(countryCounts[e.source]||0)+1);
  const topCountry=Object.entries(countryCounts).sort((a,b)=>b[1]-a[1])[0];
  if(topCountry){
    const c=countries[Number(topCountry[0])];
    document.querySelector('.metric:nth-child(3) strong').textContent=c.flag+' '+c.name;
    document.querySelector('.metric:nth-child(3) .sub').textContent=`${topCountry[1]} recent events`;
  }
}
function clock(){
  const d=new Date();
  document.getElementById('date').textContent=d.toLocaleDateString('en-CA');
  document.getElementById('time').textContent=d.toLocaleTimeString('en-GB',{hour12:false});
}
async function start(){
  setup();
  try{
    const world=await d3.json('https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json');
    drawMap(world);
  }catch(e){console.warn('World map boundaries could not load; the globe grid remains visible.',e);}
  // Seed a small initial set, then continuously create new source/target pairs.
  for(let i=0;i<5;i++){
    const event=makeEvent();event.time=new Date(Date.now()-(5-i)*1700);
    eventHistory.push(event);addEventVisual(event);
  }
  eventHistory.sort((a,b)=>b.time-a.time);
  renderPanels();renderMetrics();clock();
  requestAnimationFrame(animate);
  // Simulation cadence: 1–4 events in each roughly one-second burst.
  // Some events reverse a recent route to simulate a counter-attack.
  function launchBurst(){
    const burstSize=1+Math.floor(Math.random()*4);
    for(let i=0;i<burstSize;i++){
      let event;
      const recent=eventHistory.slice(0,8);
      if(recent.length && Math.random()<0.38){
        const previous=pick(recent);
        event={
          id:Date.now()+Math.random(),
          source:previous.target,
          target:previous.source,
          type:Math.random()<0.5?'Malicious Traffic':pick(attackTypes),
          time:new Date(),
          age:0,
          intensity:.85+Math.random()*.9,
          duration:3000+Math.random()*3600,
          counterAttack:true
        };
      }else{
        event=makeEvent();
        event.counterAttack=false;
      }
      recordEvent(event);
    }
  }
  (function scheduleBurst(){
    launchBurst();
    setTimeout(scheduleBurst,850+Math.random()*300);
  })();
  setInterval(clock,1000);
  setInterval(()=>{
    // Refresh the visible "seconds ago" labels even between incoming events.
    renderPanels();
  },5000);
}
window.addEventListener('resize',()=>{
  clearTimeout(resizeTimer);
  resizeTimer=setTimeout(()=>{
    const previous=eventHistory.slice(0,8);
    setup();
    // Rebuild the map after resizing, then re-create currently active event lights.
    d3.json('https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json').then(drawMap).catch(()=>{});
    routeData.forEach(r=>{r.group.remove();r.mover.remove();r.head.remove();r.sourcePulse.remove();r.targetHalo.remove();});
    routeData=[];
    previous.forEach(e=>addEventVisual(e));
  },120);
});
start();
