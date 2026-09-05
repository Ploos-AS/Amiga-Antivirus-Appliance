package scanner

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/Ploos-AS/Amiga-Antivirus-Appliance/internal/adf"
	archivepkg "github.com/Ploos-AS/Amiga-Antivirus-Appliance/internal/archive"
	"github.com/Ploos-AS/Amiga-Antivirus-Appliance/internal/hunk"
	"github.com/Ploos-AS/Amiga-Antivirus-Appliance/internal/signatures"
)

const MaxArchiveDepth = 2

type MemberResult struct {
	Name           string                  `json:"name"`
	Size           int64                   `json:"size"`
	SHA256         string                  `json:"sha256"`
	Format         string                  `json:"format"`
	Verdict        string                  `json:"verdict"`
	Detection      string                  `json:"detection,omitempty"`
	Error          string                  `json:"error,omitempty"`
	Archive        *archivepkg.Analysis    `json:"archive,omitempty"`
	Children       []MemberResult          `json:"children,omitempty"`
	ADF            *adf.Analysis           `json:"adf,omitempty"`
	Filesystem     *adf.FilesystemAnalysis `json:"filesystem,omitempty"`
	Hunk           *hunk.Analysis          `json:"hunk,omitempty"`
	BootblockMatch *signatures.Match       `json:"bootblock_match,omitempty"`
}

type Result struct {
	Path           string                  `json:"path"`
	Name           string                  `json:"name"`
	Size           int64                   `json:"size"`
	SHA256         string                  `json:"sha256"`
	Format         string                  `json:"format"`
	Verdict        string                  `json:"verdict"`
	Detection      string                  `json:"detection,omitempty"`
	Archive        *archivepkg.Analysis    `json:"archive,omitempty"`
	MemberResults  []MemberResult          `json:"member_results,omitempty"`
	ADF            *adf.Analysis           `json:"adf,omitempty"`
	Filesystem     *adf.FilesystemAnalysis `json:"filesystem,omitempty"`
	Hunk           *hunk.Analysis          `json:"hunk,omitempty"`
	BootblockMatch *signatures.Match       `json:"bootblock_match,omitempty"`
}

type archiveBudget struct {
	expanded int64
	members  int
}

func ScanFile(path string) (Result, error) {
	f, err := os.Open(path)
	if err != nil { return Result{}, err }
	defer f.Close()
	info, err := f.Stat()
	if err != nil { return Result{}, err }
	if !info.Mode().IsRegular() { return Result{}, fmt.Errorf("not a regular file: %s", path) }
	h := sha256.New()
	head := make([]byte, 4096)
	n, readErr := io.ReadFull(f, head)
	if readErr != nil && readErr != io.EOF && readErr != io.ErrUnexpectedEOF { return Result{}, readErr }
	head = head[:n]
	if _, err := f.Seek(0, io.SeekStart); err != nil { return Result{}, err }
	if _, err := io.Copy(h, f); err != nil { return Result{}, err }
	format := DetectFormat(path, head, info.Size())
	result := Result{Path:path, Name:filepath.Base(path), Size:info.Size(), SHA256:hex.EncodeToString(h.Sum(nil)), Format:format, Verdict:"unknown"}
	switch format {
	case "adf":
		if err := analyzeADFPath(&result, path); err != nil { return Result{}, err }
	case "adz":
		data, err := os.ReadFile(path); if err != nil { return Result{}, fmt.Errorf("read ADZ: %w", err) }
		expanded, a, err := archivepkg.DecodeADZ(data); if err != nil { return Result{}, fmt.Errorf("decode ADZ: %w", err) }
		result.Archive=a; if err:=analyzeADFBytes(&result,expanded); err!=nil{return Result{},fmt.Errorf("analyze expanded ADZ ADF: %w",err)}
	case "dms":
		data, err := os.ReadFile(path); if err != nil { return Result{}, fmt.Errorf("read DMS: %w", err) }
		expanded, a, err := archivepkg.DecodeDMS(data); if err != nil { return Result{}, fmt.Errorf("decode DMS: %w", err) }
		result.Archive=a; if err:=analyzeADFBytes(&result,expanded); err!=nil{return Result{},fmt.Errorf("analyze expanded DMS ADF: %w",err)}
	case "zip","lha","lzx":
		data,err:=os.ReadFile(path); if err!=nil{return Result{},fmt.Errorf("read %s: %w",format,err)}
		members,a,err:=decodeArchive(format,data); if err!=nil{return Result{},fmt.Errorf("decode %s: %w",format,err)}
		result.Archive=a; budget:=&archiveBudget{expanded:a.ExpandedSize,members:len(a.Members)}
		result.MemberResults=scanArchiveMembersDepth(a,members,1,budget); propagateMemberVerdict(&result)
	case "amiga-hunk-executable":
		data,err:=os.ReadFile(path); if err!=nil{return Result{},fmt.Errorf("read Hunk executable: %w",err)}; result.Hunk=hunk.Analyze(data)
	}
	return result,nil
}

func decodeArchive(format string,data []byte)([]archivepkg.ExpandedMember,*archivepkg.Analysis,error){
	switch format{case "zip":return archivepkg.DecodeZIP(data);case "lha":return archivepkg.DecodeLHA(data);case "lzx":return archivepkg.DecodeLZX(data);default:return nil,nil,fmt.Errorf("unsupported archive format: %s",format)}
}
func decodeArchiveLimited(format string,data []byte,budget *archiveBudget)([]archivepkg.ExpandedMember,*archivepkg.Analysis,error){
	remainingBytes,remainingMembers,ok:=remainingArchiveBudget(budget);if !ok{return nil,nil,fmt.Errorf("global archive safety budget exhausted")}
	switch format{case "zip":return archivepkg.DecodeZIPLimited(data,remainingBytes,remainingMembers);case "lha":return archivepkg.DecodeLHALimited(data,remainingBytes,remainingMembers);case "lzx":return archivepkg.DecodeLZXLimited(data,remainingBytes,remainingMembers);default:return nil,nil,fmt.Errorf("unsupported archive format: %s",format)}
}
func scanArchiveMembersDepth(analysis *archivepkg.Analysis,members []archivepkg.ExpandedMember,depth int,budget *archiveBudget)[]MemberResult{
	if analysis==nil{return nil};results:=make([]MemberResult,0,len(members));for i,member:=range members{head:=member.Data;if len(head)>4096{head=head[:4096]};format:=DetectFormat(member.Name,head,int64(len(member.Data)));if i<len(analysis.Members){analysis.Members[i].Format=format};sum:=sha256.Sum256(member.Data);r:=MemberResult{Name:member.Name,Size:int64(len(member.Data)),SHA256:hex.EncodeToString(sum[:]),Format:format,Verdict:"unknown"};scanMemberPayload(&r,member.Data,depth,budget);results=append(results,r)};return results
}
func scanMemberPayload(r *MemberResult,data []byte,depth int,budget *archiveBudget){
	if r==nil{return};switch r.Format{
	case "adf": tmp:=Result{Verdict:"unknown"};if err:=analyzeADFBytes(&tmp,data);err!=nil{r.Error=err.Error();return};copyADFResult(r,&tmp)
	case "amiga-hunk-executable":r.Hunk=hunk.Analyze(data)
	case "adz":
		remainingBytes,remainingMembers,ok:=remainingArchiveBudget(budget);if !ok||remainingMembers<1{r.Error="nested archive decode blocked by global safety limit";return};expanded,a,err:=archivepkg.DecodeADZLimited(data,remainingBytes);if err!=nil{r.Error=fmt.Sprintf("nested archive decode failed within global safety limit: %v",err);return};if !reserveArchiveBudget(budget,a.ExpandedSize,1){r.Error="nested archive decode blocked by global safety limit";return};r.Archive=a;tmp:=Result{Verdict:"unknown"};if err:=analyzeADFBytes(&tmp,expanded);err!=nil{r.Error=err.Error();return};copyADFResult(r,&tmp)
	case "dms":
		remainingBytes,remainingMembers,ok:=remainingArchiveBudget(budget);if !ok||remainingMembers<1{r.Error="nested archive decode blocked by global safety limit";return};expanded,a,err:=archivepkg.DecodeDMSLimited(data,remainingBytes);if err!=nil{r.Error=fmt.Sprintf("nested DMS decode failed within global safety limit: %v",err);return};if !reserveArchiveBudget(budget,a.ExpandedSize,1){r.Error="nested archive decode blocked by global safety limit";return};r.Archive=a;tmp:=Result{Verdict:"unknown"};if err:=analyzeADFBytes(&tmp,expanded);err!=nil{r.Error=err.Error();return};copyADFResult(r,&tmp)
	case "zip","lha","lzx":
		if depth>=MaxArchiveDepth{r.Error=fmt.Sprintf("nested archive depth exceeds limit %d",MaxArchiveDepth);return};members,a,err:=decodeArchiveLimited(r.Format,data,budget);if err!=nil{r.Error=fmt.Sprintf("nested archive decode failed within global safety limit: %v",err);return};if !reserveArchiveBudget(budget,a.ExpandedSize,len(a.Members)){r.Error="nested archive decode blocked by global safety limit";return};r.Archive=a;r.Children=scanArchiveMembersDepth(a,members,depth+1,budget);propagateChildVerdict(r)
	}
}
func remainingArchiveBudget(b *archiveBudget)(int64,int,bool){if b==nil||b.expanded<0||b.members<0{return 0,0,false};rb:=archivepkg.MaxExpandedSize-b.expanded;rm:=archivepkg.MaxMembers-b.members;if rb<=0||rm<=0{return 0,0,false};return rb,rm,true}
func reserveArchiveBudget(b *archiveBudget,e int64,m int)bool{if b==nil||e<0||m<0{return false};if e>archivepkg.MaxExpandedSize-b.expanded||m>archivepkg.MaxMembers-b.members{return false};b.expanded+=e;b.members+=m;return true}
func copyADFResult(r *MemberResult,t *Result){r.ADF=t.ADF;r.Filesystem=t.Filesystem;r.BootblockMatch=t.BootblockMatch;r.Verdict=t.Verdict;r.Detection=t.Detection}
func propagateChildVerdict(m *MemberResult){if m==nil{return};for _,c:=range m.Children{if c.Verdict=="infected"{m.Verdict="infected";m.Detection="archive-member:"+c.Name+":"+c.Detection;return}}}
func propagateMemberVerdict(r *Result){if r==nil{return};for _,m:=range r.MemberResults{if m.Verdict=="infected"{r.Verdict="infected";r.Detection="archive-member:"+m.Name+":"+m.Detection;return}}}
func analyzeADFPath(r *Result,path string)error{a,err:=adf.AnalyzeFile(path);if err!=nil{return fmt.Errorf("analyze ADF: %w",err)};r.ADF=a;if err:=applyBundledBootblockDatabase(r);err!=nil{return err};if !a.DOSHeaderRecognized{return nil};fs,err:=adf.AnalyzeFilesystem(path);if err!=nil{return fmt.Errorf("analyze ADF filesystem: %w",err)};r.Filesystem=fs;return nil}
func analyzeADFBytes(r *Result,image []byte)error{a,err:=adf.Analyze(bytes.NewReader(image),int64(len(image)));if err!=nil{return err};r.ADF=a;if err:=applyBundledBootblockDatabase(r);err!=nil{return err};if !a.DOSHeaderRecognized{return nil};fs,err:=adf.AnalyzeFilesystemBytes(image);if err!=nil{return fmt.Errorf("analyze ADF filesystem: %w",err)};r.Filesystem=fs;return nil}
func applyBundledBootblockDatabase(r *Result)error{db,err:=signatures.LoadBundled();if err!=nil{return fmt.Errorf("load bootblock signatures: %w",err)};applyBootblockDatabase(r,db);return nil}
func applyBootblockDatabase(r *Result,db *signatures.Database){if r==nil||r.ADF==nil||db==nil{return};match:=db.Lookup(r.ADF.BootblockSHA256);r.BootblockMatch=match;if match!=nil&&match.Status==signatures.StatusKnownMalicious{r.Verdict="infected";r.Detection="bootblock:"+match.Name}}
func DetectFormat(path string,head []byte,size int64)string{
	if size==adf.DDSize||size==adf.HDSize{return "adf"};if len(head)>=4&&string(head[:3])=="DOS"&&head[3]<=7{return "amiga-filesystem-image"};if len(head)>=4&&string(head[:4])=="DMS!"{return "dms"};if len(head)>=4&&head[0]=='P'&&head[1]=='K'&&(head[2]==3||head[2]==5||head[2]==7){return "zip"};if len(head)>=2&&head[0]==0x1f&&head[1]==0x8b{if strings.EqualFold(filepath.Ext(path),".adz"){return "adz"};return "gzip"};if len(head)>=7&&head[2]=='-'&&head[3]=='l'&&head[4]=='h'&&head[6]=='-'{return "lha"};if len(head)>=4&&binary.BigEndian.Uint32(head[:4])==hunk.HUNK_HEADER{return "amiga-hunk-executable"};ext:=strings.ToLower(filepath.Ext(path));switch ext{case ".adf":return "adf-unrecognized";case ".adz":return "adz-unrecognized";case ".dms":return "dms-unrecognized";case ".lha",".lzh":return "lha-unrecognized";case ".lzx":return "lzx";case ".hdf":return "hdf"};return "unknown"
}
