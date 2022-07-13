//analyze.rs

use configuration::Config;
pub use disasm::*;
use std::collections::VecDeque;
use colored::*;
use std::fmt::Write;
use memmap::MmapMut;
use serde_json;
use std::collections::BTreeMap;
use std::collections::BTreeSet;


//x86 imports
use arch::x86::emulatex86::*;
use arch::x86::analyzex86::*;
use arch::x86::cpux86::*;
use analysis::formats::peloader::*;
use analysis::signature_analysis::SigAnalyzer;
use analysis::data_analyzer::{scan_for_function_blocks, rename_indirect_calls};

pub const STACK_ADDRESS: u64 = 0x200000;
pub const MAX_LOOPS: usize = 10;

#[derive(Debug, Copy, Clone, Serialize)]
pub enum BinaryType{
    BIN, //Default case
    PE,
    PEEXE,
    PEDLL,
    PENET,
    PESYS,
    ELF,
    MACHO,
}

pub struct Analysis
{
    pub xi: Xori, 
    pub base: usize,
    pub disasm: String,
    pub functions: String,
    pub header: String,
}

#[derive(Debug,Clone,Serialize, Deserialize)]
pub struct FuncInfo
{
    pub address: u64,
    pub mem_address: u64,
    pub xrefs: BTreeSet<u64>,
    pub name: String,
    pub argc: usize,
    pub mem_type: MemoryType,
    pub returns: BTreeSet<u64>,
    pub return_values: BTreeMap<u64, u64>,
    pub jumps: BTreeMap<u64, Jump>,
}

#[derive(Debug,Clone,Serialize, Deserialize)]
pub struct Jump
{
    pub left: i64,
    pub right: i64,
}

#[derive(Debug,Clone,Serialize)]
pub struct Header
{
    pub binary_type: BinaryType,
    pub image_base: u64,
    pub base_of_code: u64,
    pub size_of_code: u64,
    pub base_of_data: u64,
    pub address_of_entry_point: u64,
    pub stack_size: u64,
    pub section_alignment: u64,
    pub file_alignment: u64,
    pub mode: Mode,
    pub image_data_directory: u64,
    pub import_table: Option<Vec<Import>>,
    pub size_of_image: u64,
    pub section_table: Option<Vec<Section>>,
}

impl Header
{
    pub fn new()->Header 
    {
        Header{
            binary_type: BinaryType::BIN,
            image_base: 0x1000,
            base_of_code: 0,
            size_of_code: 0,
            base_of_data: 0,
            address_of_entry_point: 0,
            stack_size: STACK_ADDRESS,
            section_alignment: 0,
            file_alignment: 0,
            mode: Mode::Mode32,
            image_data_directory: 0,
            import_table: None,
            size_of_image: 0,
            section_table: None,
        }
    }
    fn parse(&mut self, data: &mut [u8], config: &Config) -> Result<i32, String>
    {
        match self.identify(data)
        {
            BinaryType::BIN=>
            {

                debug!("binary data header not parsed");
            },
            BinaryType::PE=>
            {
                debug!("parsing PE header");
                match get_pe_header(self, data, config)
                {
                    Ok(_)=>{
                    },
                    Err(_err)=>return Err(_err),
                }
            },
            BinaryType::ELF=>return Err(format!("ELF is not supported yet")),
            BinaryType::MACHO=>return Err(format!("MACHO is not supported yet")),
            _=>return Err(format!("Unsupported format")),
        }
        return Ok(0);
    }
    fn identify(&mut self, binary: &mut [u8]) -> BinaryType {
        self.binary_type = match binary {
            &mut [0x7f, 0x45, 0x4c, 0x46, 0x02, 0x02, 0x01, ..] => BinaryType::ELF,
            &mut [0x4d, 0x5a, ..] => BinaryType::PE,
            &mut [0xfe, 0xed, 0xfa, 0xce, ..] => BinaryType::MACHO,
            _ => BinaryType::BIN,
        };
        self.binary_type
    }
}

fn hex_array(
    arr: &[u8; 16], 
    len: usize) -> String 
{
    let mut s = String::new();
    for i in 0..len 
    {
        let byte = arr[i];
        write!(&mut s, "{:02X} ", byte).expect("Unable to write");
    }
    return s;
}

fn display_disassembly(analysis: &mut Analysisx86){
    for (_key, item) in analysis.instr_info.iter_mut()
    {
        let addr: String = format!("0x{:x}", item.instr.address);
        let mut detail: String = String::new();
        if item.detail.len() > 0 {
            for d in item.detail.iter()
            {
                if !d.contents.is_empty(){
                    detail = format!("{}; {}", detail, d.contents);
                } 
            }
              
        }
        println!("{:16} {:20} {} {} {}", 
            addr.yellow(), 
            hex_array(&item.instr.bytes, item.instr.size).white(),
            item.instr.mnemonic,
            item.instr.op_str,
            detail.green());
    }
}

// Only x86 for now
fn disassemble_init(
    _arch: &Arch,
    _header: Header,
    _binary: &mut [u8],
    _config: &Config) -> Option<Analysisx86>
{
    debug!("disassemble()");
    match *_arch{
        Arch::ArchX86 =>
        {
            // Needed for PE Lifetime
            // Handle Image Building
            let mut new_binary = MmapMut::map_anon(1.max(_header.size_of_image as usize))
                .expect("failed to map the file");
            let mut teb: Vec<u8> = Vec::new();
            let mut peb: Vec<u8> = Vec::new();

            let mut analysis_queue: VecDeque<Statex86> = VecDeque::new();
            let mut mem_manager: MemoryManager = MemoryManager{ list: Vec::new() };
            let mut analysis: Analysisx86 = Analysisx86 
            {
                xi: Xori { arch: Arch::ArchX86, mode: _header.mode },
                base: _header.image_base as usize,
                header: _header,
                address_tracker: BTreeMap::new(),
                instr_info: BTreeMap::new(),
                functions: Vec::new(),
                symbols: None,
                sig_analyzer: SigAnalyzer::new(),
            };

            let code_start = analysis.base + analysis.header.base_of_code as usize;
            let data_start = analysis.base + analysis.header.base_of_data as usize;
            let entry_point = analysis.base + analysis.header.address_of_entry_point as usize;

            println!("IMAGE START: {:10x}", analysis.base);
            println!("CODE START: {:10x}", code_start);
            println!("ENTRYPOINT: {:10x}", entry_point);
            println!("ARCH: {:?}", analysis.xi.arch);
            println!("MODE: {:?}", analysis.xi.mode);

            /* Initialize Signature Analyzer */
            analysis.sig_analyzer.init(
                _config, 
                &analysis.xi.arch, 
                &analysis.xi.mode, 
                &analysis.header.binary_type);

            // Initalize the CPU state
            let mut state = Statex86{
                offset: entry_point,
                cpu: CPUStatex86::new(), 
                stack: Vec::new(),
                current_function_addr: entry_point as u64,
                emulation_enabled: _config.x86.emulation_enabled, 
                loop_state: LoopState{
                    max_loops: _config.x86.loop_default_case, 
                    is_loop: false,
                    forward_addr: Vec::new(),
                    loop_tracker: Vec::new()
                },
                analysis_type: AnalysisType::Code,
            };

            // Initalize the segement registers 
            state.cpu.address_size = analysis.xi.mode.get_size() as u8;
            state.cpu.stack_address = _config.x86.stack_address + analysis.header.stack_size;
            state.cpu.segments.ss = state.cpu.stack_address as i64;
            state.cpu.segments.cs = code_start as i64;
            state.cpu.segments.ds = data_start as i64;
            state.cpu.regs.esp.value = state.cpu.stack_address as i64;

            match analysis.header.binary_type
            {
                BinaryType::PE |
                BinaryType::PEEXE | 
                BinaryType::PEDLL | 
                BinaryType::PESYS | 
                BinaryType::PENET =>
                {           
                    build_pe(
                        _config,
                        _binary,
                        &mut new_binary,
                        &mut teb,
                        &mut peb,
                        &mut state,
                        &mut analysis,
                        &mut mem_manager,
                        &mut analysis_queue);
                },
                _=>
                {
                    // Initialize memorybounds for the main binary
                    mem_manager.list.push(MemoryBounds
                    {
                        base_addr: analysis.base,
                        size: _binary.len(),
                        mem_type: MemoryType::Image,
                        binary: _binary,
                    });
                },
            }

            // Initialize stack memory bounds 
            mem_manager.list.push(
            MemoryBounds
            {
                base_addr: _config.x86.stack_address as usize,
                size: analysis.header.stack_size as usize,
                mem_type: MemoryType::Stack,
                binary: &mut [0u8; 0],
            });

            // Add the EntryPoint as the starting function
            analysis.functions.push(FuncInfo
            {
                address: entry_point as u64,
                mem_address: 0,
                xrefs: BTreeSet::new(),
                name: String::from("EntryPoint"),
                argc: 0,
                mem_type: MemoryType::Image,
                returns: BTreeSet::new(),
                return_values: BTreeMap::new(),
                jumps: BTreeMap::new(),
            });

            let mut code_start_state = state.clone();
            let mut data_start_state = state.clone();
            analysis_queue.push_front(state);
            
            // Each new state will be processed in this queue
            // State is incremented by state.offset
            // PASS 1
            while !analysis_queue.is_empty()
            {
                let mut new_state = analysis_queue.pop_front();
                match new_state{
                    Some(ref mut nstate)=>
                    {
                        recurse_disasmx86(
                            &mut analysis, 
                            &mut mem_manager,
                            nstate, 
                            &mut analysis_queue);
                    }
                    None=>{},
                }
            }

            
            if !code_start_state.emulation_enabled {
                // PASS 2 reanalyze beginning of Code
                code_start_state.offset = code_start;
                code_start_state.current_function_addr=0;
                code_start_state.analysis_type = AnalysisType::Data;
                analysis_queue.push_front(code_start_state);

                while !analysis_queue.is_empty()
                {
                    let mut new_state = analysis_queue.pop_front();
                    match new_state{
                        Some(ref mut nstate)=>
                        {
                            recurse_disasmx86(
                                &mut analysis, 
                                &mut mem_manager,
                                nstate, 
                                &mut analysis_queue);
                        }
                        None=>{},
                    }
                }

                // PASS 3 data
                data_start_state.offset = data_start;
                data_start_state.current_function_addr=0;
                data_start_state.analysis_type = AnalysisType::Data;

                analysis_queue.push_front(data_start_state);

                while !analysis_queue.is_empty()
                {
                    let mut new_state = analysis_queue.pop_front();
                    match new_state{
                        Some(ref mut nstate)=>
                        {
                            recurse_disasmx86(
                                &mut analysis, 
                                &mut mem_manager,
                                nstate, 
                                &mut analysis_queue);
                        }
                        None=>{},
                    }
                }
            }

            // Function Block Renaming
            if _config.x86.flirt_enabled {
                scan_for_function_blocks(
                    &mut analysis, 
                    &mut mem_manager);
            }

            rename_indirect_calls(
                &mut analysis);

            return Some(analysis);      
        },
        _=>{},
    }
    return None;
}

/// This is the main function that analyzes the binary
/// based on type.
/// NOTE: Only x86 Binary and PEs are supported.
/// 
/// # Example:
/// 
/// ```rust,ignore
/// let mut binary32= b"\xe9\x1e\x00\x00\x00\xb8\x04\
/// \x00\x00\x00\xbb\x01\x00\x00\x00\x59\xba\x0f\
/// \x00\x00\x00\xcd\x80\xb8\x01\x00\x00\x00\xbb\
/// \x00\x00\x00\x00\xcd\x80\xe8\xdd\xff\xff\xff\
/// \x48\x65\x6c\x6c\x6f\x2c\x20\x57\x6f\x72\x6c\
/// \x64\x21\x0d\x0a".to_vec();
/// let mut config_map: Option<Value> = None;
/// if Path::new("xori.json").exists()
/// {
///     config_map = read_config(&Path::new("xori.json"));
/// } 
/// match analyze(&Arch::ArchX86, &mut binary32, &config_map)
/// {
///     Some(analysis)=>{
///         if !analysis.disasm.is_empty(){
///             println!("{}", analysis.disasm);
///          }
///     },
///     None=>{},
/// }
/// ```   
pub fn analyze(
    arch: &Arch,
    mode: &Mode, 
    binary: &mut [u8], 
    config: &Config) -> Option<Analysis>
{
    debug!("analyze()");
    // Identify
    let mut header = Header::new();
    match header.parse(binary, config)
    {
        Ok(_)=>{},
        Err(_err)=>
        {
            println!("{:?}", _err);
            return None;
        }
    }
    match header.binary_type{
        BinaryType::BIN=>
        {
            match arch
            {
                Arch::ArchX86=>{
                    header.image_base = match config.x86.start_address{ 0=>0x1000, _=>config.x86.start_address };
                    header.address_of_entry_point = config.x86.entry_point;
                    header.stack_size = match config.x86.stack_size{ 0=>STACK_ADDRESS, _=>config.x86.stack_size };
                },
                _=>{},
            }
            debug!("Identified binary data");
            header.size_of_image = binary.len() as u64;
            header.mode = *mode;

            let some_analysis = disassemble_init(
                arch, 
                header, 
                binary, 
                config);
            // disassemble
            // default arch is x86
            match some_analysis {
                Some( mut analysis )=>{
                    let result_functions = match config.x86.output.functions
                    {
                        true=>serde_json::to_string(&analysis.functions).unwrap_or(String::new()),
                        false=>String::new(),
                    };
                    
                    let result_header = match config.x86.output.imports
                    {
                        true=>serde_json::to_string(&analysis.header).unwrap_or(String::new()),
                        false=>String::new(),
                    };

                    let result_disasm = match config.x86.output.disasm_json
                    {
                        true=>serde_json::to_string(&analysis.instr_info).unwrap_or(String::new()),
                        false=>String::new(),
                    };

                    if config.x86.output.disassembly
                    {
                        display_disassembly(&mut analysis);
                    }

                    /* Handle output */
                    let result = Analysis {
                        xi: analysis.xi, 
                        base: analysis.base,
                        disasm: result_disasm,
                        functions: result_functions,
                        header: result_header,
                    };

                    return Some(result);
                },
                None=>{},
            }
        },
        BinaryType::PE |
        BinaryType::PEEXE | 
        BinaryType::PEDLL | 
        BinaryType::PESYS | 
        BinaryType::PENET =>
        {
            debug!("Identified PE");
            // parse
            if header.address_of_entry_point == 0 
            {
                error!("not a valid PE header");
                return None;
            }
            // disassemble
            // default arch is x86
            let some_analysis = disassemble_init(
                arch,
                header, 
                binary,
                config);

            match some_analysis {
                Some( mut analysis )=>{
                    /* Handle output */
                    let result_functions = match config.x86.output.functions
                    {
                        true=>serde_json::to_string(&analysis.functions).unwrap_or(String::new()),
                        false=>String::new(),
                    };
                    
                    let result_header = match config.x86.output.imports
                    {
                        true=>serde_json::to_string(&analysis.header).unwrap_or(String::new()),
                        false=>String::new(),
                    };

                    let result_disasm = match config.x86.output.disasm_json
                    {
                        true=>serde_json::to_string(&analysis.instr_info).unwrap_or(String::new()),
                        false=>String::new(),
                    };

                    if config.x86.output.disassembly
                    {
                        display_disassembly(&mut analysis);
                    }

                    /* Handle output */
                    let result = Analysis {
                        xi: analysis.xi, 
                        base: analysis.base,
                        disasm: result_disasm,
                        functions: result_functions,
                        header: result_header,
                    };
                    
                    return Some(result);
                },
                None=>{},
            }            
        },
        BinaryType::ELF=>
        {
            error!("ELF is not supported yet.");
        },
        BinaryType::MACHO=>
        {
            error!("Macho is not supported yet.");
        },
    }
    return None;
}
