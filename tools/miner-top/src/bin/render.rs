//! Headless render of real miner-top frames → HTML "screenshot".
use std::fmt::Write as _;
use std::fs;
use coincync_miner_top::miner::Miner;
use coincync_miner_top::ui::draw;
use ratatui::{backend::TestBackend, buffer::Buffer, style::{Color, Modifier}, Terminal};

const W: u16 = 132; const H: u16 = 30; const INK: &str = "#0f201d";

fn hex(c: Color, fg: bool) -> String { match c {
    Color::Rgb(r,g,b) => format!("#{:02x}{:02x}{:02x}", r,g,b),
    Color::Black => "#0f201d".into(), Color::White|Color::Gray => "#ece3cf".into(),
    Color::DarkGray => "#8ba095".into(), Color::Red => "#cd6d49".into(),
    Color::Green => "#82b18a".into(), Color::Yellow => "#e0ac47".into(), Color::Cyan => "#74a7ae".into(),
    Color::Reset => if fg {"#ece3cf".into()} else {INK.into()},
    _ => if fg {"#ece3cf".into()} else {INK.into()},
}}
fn esc(s:&str)->String{s.replace('&',"&amp;").replace('<',"&lt;").replace('>',"&gt;")}

fn dump(buf:&Buffer)->String{
    let mut out=String::new();
    for y in 0..H {
        let (mut cf,mut cb,mut cbold,mut open,mut run)=(String::new(),String::new(),false,false,String::new());
        macro_rules! flush {()=>{ if open { let w=if cbold{"font-weight:700;"}else{""};
            let bg=if cb==INK{String::new()}else{format!("background:{cb};")};
            let _=write!(out,"<span style=\"color:{cf};{bg}{w}\">{}</span>",esc(&run)); run.clear(); open=false; }}}
        for x in 0..W {
            let cell=&buf[(x,y)]; let fg=hex(cell.fg,true); let bg=hex(cell.bg,false);
            let bold=cell.modifier.contains(Modifier::BOLD)||cell.modifier.contains(Modifier::REVERSED);
            let (fg,bg)= if cell.modifier.contains(Modifier::REVERSED){(bg,fg)}else{(fg,bg)};
            if open && (fg!=cf||bg!=cb||bold!=cbold){flush!();}
            if !open {cf=fg;cb=bg;cbold=bold;open=true;} run.push_str(cell.symbol());
        }
        flush!(); out.push('\n');
    }
    out
}

fn frame(threads:usize, ticks:usize, block:bool)->String{
    let mut m=Miner::new("rig-01",threads);
    let clocks=["13:56:41","13:56:44","13:56:47","13:56:50","13:56:54"];
    for i in 0..ticks { m.simulate(clocks[i%clocks.len()].into()); }
    if block { m.force_block("13:56:54".into()); }
    let mut t=Terminal::new(TestBackend::new(W,H)).unwrap();
    t.draw(|f| draw(f,&m)).unwrap();
    dump(t.backend().buffer())
}

fn main(){
    let running=frame(8,120,false);
    let hit=frame(8,120,true);
    let page=format!(r#"<!doctype html><html><head><meta charset="utf-8"><title>miner-top</title>
<style>body{{background:#0a1512;color:#ece3cf;font-family:-apple-system,Segoe UI,Roboto,sans-serif;margin:0;padding:28px}}
h1{{font-weight:600;font-size:22px;margin:0 0 4px}}p.sub{{color:#8ba095;margin:0 0 22px;font-size:14px}}
h2{{font-size:13px;letter-spacing:.05em;color:#96763a;margin:26px 0 8px;font-family:ui-monospace,Menlo,monospace}}
.term{{background:{INK};border:1px solid #284c45;border-radius:6px;padding:12px 14px;overflow-x:auto}}
pre{{margin:0;font-family:"Cascadia Code","JetBrains Mono",ui-monospace,Menlo,Consolas,monospace;font-size:12.5px;line-height:1.25;white-space:pre}}</style></head><body>
<h1>coincync miner-top — RandomX dashboard</h1>
<p class="sub">Real ratatui frames rendered headlessly — exactly what prints in your terminal.</p>
<h2>MINING</h2><div class="term"><pre>{running}</pre></div>
<h2>BLOCK FOUND</h2><div class="term"><pre>{hit}</pre></div>
</body></html>"#);
    fs::write("miner-top-preview.html",page).unwrap();
    println!("wrote miner-top-preview.html");
}
