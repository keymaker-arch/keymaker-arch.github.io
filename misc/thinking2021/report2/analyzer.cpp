#include "llvm/Pass.h"
#include "llvm/IR/Function.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include "llvm/IR/TypeFinder.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Type.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/DebugLoc.h"



#include <map>
#include <vector>
#include <string>
#include <iterator>
#include <fstream>
#include <istream>

using namespace llvm;

namespace {

  class Analyzer {
    public:
      struct srd{
        std::string struct_name;
        std::vector<int> fptr_off;
      };
      
      // this map STL store the interesting structs
      std::map<std::string, struct srd*> struct_entries;


    private:
      // inspect a field in a struct, recursive if the field is a struct
      unsigned long iterateStructField(Type *T, unsigned long curOff, struct srd* record_p){
        if(T->isStructTy()){  // in case the type is struct, we need to iterate over its field recursively
          if(auto* ST = dyn_cast<llvm::StructType>(T)){
            for(auto *fieldT : ST->elements()){
              curOff = iterateStructField(fieldT, curOff, record_p);
            }
          }
        }else{
          if(T->isPointerTy()){ // identify function pointer, return its offset
            if(auto* ptype = dyn_cast<PointerType>(T)){
              if(ptype->getElementType()->isFunctionTy()){
                record_p->fptr_off.push_back(curOff);
              }
            }
          }
          curOff += getTypeBytes(T);
        }
        return curOff;
      }

      // check if a call instruction is a heap allocation, by checking its function name
      bool isHeapAllocate(CallInst* CI){
        StringRef sr = CI->getCalledFunction()->getName();
        if(!sr.str().compare("malloc")) return true;
        return false;
      }

      // check if destination type of the cast instruction is an interesting struct type
      bool isCastInteresting(CastInst* CSTI){
        if(auto* ptype_src = dyn_cast<PointerType>(CSTI->getSrcTy())){
          if(auto* ptype_dst = dyn_cast<PointerType>(CSTI->getDestTy())){
            if(ptype_src->getElementType()->isIntegerTy() && ptype_dst->getElementType()->isStructTy()){
              std::string dst_struct_name = ptype_dst->getElementType()->getStructName().str();
              // check if the struct name is a key in interesting struct map
              if(struct_entries.find(dst_struct_name) == struct_entries.end()){
                return false;
              }else{
                return true;
              }
            }
          }
        }
        return false;
      }

      // return the byte len of a given type
      unsigned long getTypeBytes(Type *T){
        if(T->isPointerTy()) return 8;
        auto sizeBits = T->getPrimitiveSizeInBits();
        return sizeBits/8;
      }

      // check found an allocation site of an interesting struct
      bool isInterestingAllocation(inst_iterator I){
        Instruction* pinst = &*I;
        if(CallInst* CI = dyn_cast<CallInst>(pinst)){  // is a call instruction
          if(isHeapAllocate(CI)){ // is a heap allocate instruction
            // inst_iterator nextI = I + 1;
            // pinst = &*nextI;
            I++;
            pinst = &*I;
            if(CastInst* CSTI = dyn_cast<CastInst>(pinst)){ // next instruction is a cast
              if(isCastInteresting(CSTI)){ // the cast is interesting
                // errs() << "interesting site spotted\n";
                I--;
                return true;
              }
            }
          }
        }
        I--;
        return false;
      }

    public:

      void printEntries(char* file_name){
        std::map<std::string, struct srd*>::iterator itr;
        if(!file_name){
          for(itr = struct_entries.begin();itr!=struct_entries.end();itr++){
            errs() << itr->first << " ";
            for(auto i : itr->second->fptr_off){
              errs() << i << " ";
            }
            errs()<< "\n";
          }
        }else{
          std::ofstream fs(file_name);
          for(itr = struct_entries.begin();itr!=struct_entries.end();itr++){
            fs << itr->first << " ";
            for(auto i : itr->second->fptr_off){
              fs << i << " ";
            }
            fs << "\n";
          }
        }
      }

      // iterate through a module and identify interesting structs in it
      void identifyStructs(Module &M){
        unsigned long off_in_struct = 0;
        struct srd* srdp;
        for(auto *S : M.getIdentifiedStructTypes()){
          off_in_struct = 0;
          srdp = new struct srd;
          srdp->struct_name = (S->getName().data());
          for(auto *T : S->elements()){ // iterate through fields of a struct, store offset of interesting sites
            off_in_struct = iterateStructField(T, off_in_struct, srdp);            
          }
          
          // if interesting sites found in the struct, add it to the map
          if(srdp->fptr_off.empty()){
            delete srdp;
          }else{
            struct_entries[srdp->struct_name] = srdp;
          }
        }
      }

      // iterate through every instruction in a module to find interesting site
      void identifyInterstingSite(Module &M){
        for(auto& F : M){
          for(auto& B : F){
            for(inst_iterator I = inst_begin(F), E = inst_end(F); I != E; ++I){
              Instruction *pinst = &*I;
              if(isInterestingAllocation(I)){
                errs() << "interesting site spotted in " << M.getSourceFileName() << " L:" << I->getDebugLoc().getLine() << "\n";
              }
              
            }
          }
        }
      }

      void run(Module &M){
        identifyStructs(M);
        identifyInterstingSite(M);
        printEntries(NULL);
      }

  };

  struct SkeletonPass : public ModulePass {
    static char ID;
    SkeletonPass() : ModulePass(ID) {}

    virtual bool runOnModule(Module &M) {
      Analyzer Al;
      Al.run(M);
      return false;
    }
  };
}

char SkeletonPass::ID = 0;

static RegisterPass<SkeletonPass> X("hello", "Hello World Pass",
                             false /* Only looks at CFG */,
                             false /* Analysis Pass */);

static RegisterStandardPasses Y(
    PassManagerBuilder::EP_EarlyAsPossible,
    [](const PassManagerBuilder &Builder,
       legacy::PassManagerBase &PM) { PM.add(new SkeletonPass()); });
