#include "xbox2pc/binary_validation.hpp"
#include <algorithm>
#include <cstdint>
#include <string>
#include <utility>
#include "xbox2pc/diagnostics.hpp"
#include "xbox2pc/pe_parser.hpp"
namespace xbox2pc::validation {
namespace {
Stage make_stage(const char* name, StageStatus status, std::string finding = {}) {
    Stage s; s.name=name; s.status=status;
    if (!finding.empty()) s.findings.push_back(std::move(finding));
    return s;
}
bool fits(std::uint64_t start, std::uint64_t length, std::uint64_t limit) {
    return start <= limit && length <= limit - start;
}
}
const char* status_name(StageStatus s) {
    switch (s) {
        case StageStatus::Passed: return "PASSED";
        case StageStatus::Warning: return "WARNING";
        case StageStatus::Failed: return "FAILED";
        case StageStatus::NotTested: return "NOT_TESTED";
    }
    return "NOT_TESTED";
}
bool BinaryReport::structurally_valid() const {
    return parsed && std::none_of(stages.begin(), stages.end(),
        [](const Stage& s) { return s.status == StageStatus::Failed; });
}
BinaryReport validate_pe(const std::uint8_t* data, std::size_t size,
                         const std::string& source_name) {
    BinaryReport r; r.source=source_name; r.file_size=static_cast<std::uint64_t>(size);
    if (data == nullptr || size == 0) {
        r.stages.push_back(make_stage("identification", StageStatus::Failed,
            "input buffer is null or empty"));
        return r;
    }
    xbox2pc::diag::Diagnostics diagnostics;
    xbox2pc::pe::PeImage img;
    try {
        img=xbox2pc::pe::parse(data,size,source_name,diagnostics); r.parsed=true;
    } catch (const xbox2pc::pe::ParseError& e) {
        r.stages.push_back(make_stage("pe-structure",StageStatus::Failed,e.what()));
        r.stages.push_back(make_stage("imports",StageStatus::NotTested));
        r.stages.push_back(make_stage("relocations",StageStatus::NotTested));
        r.stages.push_back(make_stage("tls",StageStatus::NotTested));
        r.stages.push_back(make_stage("memory-layout",StageStatus::NotTested));
        return r;
    } catch (const std::exception& e) {
        r.stages.push_back(make_stage("pe-structure",StageStatus::Failed,
            std::string("parser exception: ")+e.what()));
        return r;
    }
    r.is_pe32_plus_amd64=img.opt.is_pe32plus &&
        img.coff.machine==xbox2pc::pe::kMachineAmd64;
    r.stages.push_back(make_stage("identification",StageStatus::Passed,
        "PE signature and headers parsed"));
    Stage structure=make_stage("pe-structure",StageStatus::Passed);
    if (!img.opt.is_pe32plus) {
        structure.status=StageStatus::Failed; structure.findings.push_back("image is not PE32+");
    }
    if (img.coff.machine!=xbox2pc::pe::kMachineAmd64) {
        structure.status=StageStatus::Failed; structure.findings.push_back("machine is not AMD64");
    }
    for (std::size_t i=0;i<img.sections.size();++i) {
        const auto& a=img.sections[i];
        const std::uint64_t aspan=std::max(a.virtual_size,a.size_of_raw_data);
        if (!fits(a.virtual_address,aspan,img.opt.size_of_image)) {
            structure.status=StageStatus::Failed;
            structure.findings.push_back("section "+a.name+" exceeds SizeOfImage");
        }
        if (a.has_raw_data && !fits(a.raw_data_offset,a.size_of_raw_data,size)) {
            structure.status=StageStatus::Failed;
            structure.findings.push_back("section "+a.name+" raw bytes exceed file");
        }
        if ((a.characteristics&xbox2pc::pe::sect_flags::kWritable) &&
            (a.characteristics&xbox2pc::pe::sect_flags::kExecutable)) {
            if (structure.status!=StageStatus::Failed) structure.status=StageStatus::Warning;
            structure.findings.push_back("section "+a.name+" is writable and executable");
        }
        for (std::size_t j=i+1;j<img.sections.size();++j) {
            const auto& b=img.sections[j];
            const std::uint64_t bspan=std::max(b.virtual_size,b.size_of_raw_data);
            const std::uint64_t ae=static_cast<std::uint64_t>(a.virtual_address)+aspan;
            const std::uint64_t be=static_cast<std::uint64_t>(b.virtual_address)+bspan;
            if (aspan && bspan && a.virtual_address<be && b.virtual_address<ae) {
                structure.status=StageStatus::Failed;
                structure.findings.push_back("virtual sections overlap: "+a.name+" and "+b.name);
            }
        }
    }
    if (img.opt.address_of_entry_point!=0) {
        const auto ep=img.opt.address_of_entry_point;
        const auto it=std::find_if(img.sections.begin(),img.sections.end(),[ep](const xbox2pc::pe::Section& s) {
            const std::uint64_t span=std::max(s.virtual_size,s.size_of_raw_data);
            return ep>=s.virtual_address &&
                static_cast<std::uint64_t>(ep)-s.virtual_address<span;
        });
        if (it==img.sections.end()) {
            structure.status=StageStatus::Failed;
            structure.findings.push_back("entry point is outside all sections");
        } else if ((it->characteristics&xbox2pc::pe::sect_flags::kExecutable)==0) {
            structure.status=StageStatus::Failed;
            structure.findings.push_back("entry point section is not executable");
        }
    } else if ((img.coff.characteristics&0x2000u)==0 &&
               structure.status==StageStatus::Passed) {
        structure.status=StageStatus::Warning;
        structure.findings.push_back("executable image has no entry point");
    }
    if (structure.findings.empty())
        structure.findings.push_back("header, section and entry-point checks passed");
    r.stages.push_back(std::move(structure));
    r.stages.push_back(make_stage("imports",StageStatus::Passed,
        std::to_string(img.imports.entries.size())+" descriptor(s) parsed; resolution not tested"));
    Stage reloc=make_stage("relocations",StageStatus::NotTested,
        "relocation application is not performed");
    if (img.directories.size()>xbox2pc::pe::kDirReloc &&
        img.directories[xbox2pc::pe::kDirReloc].rva)
        reloc.findings.push_back("base-relocation directory is present");
    else reloc.findings.push_back("no base-relocation directory");
    r.stages.push_back(std::move(reloc));
    Stage tls=make_stage("tls",StageStatus::NotTested,
        "TLS callback validation and execution are not performed");
    if (img.directories.size()>xbox2pc::pe::kDirTls &&
        img.directories[xbox2pc::pe::kDirTls].rva)
        tls.findings.push_back("TLS directory is present");
    else tls.findings.push_back("no TLS directory");
    r.stages.push_back(std::move(tls));
    r.stages.push_back(make_stage("memory-layout",StageStatus::NotTested,
        "no guest address space is created; W^X is statically reported only"));
    return r;
}
} // namespace xbox2pc::validation
