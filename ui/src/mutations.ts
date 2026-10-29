import { useMutation, useQueryClient } from '@tanstack/solid-query';
import { addBlock, removeBlock, type Block } from './api';
import { parseTtl } from './format';

/** Add a block with an optimistic row; roll back on error, refetch when settled. */
export function useAddBlock() {
  const qc = useQueryClient();
  return useMutation(() => ({
    mutationFn: (v: { cidr: string; ttl: string }) => addBlock(v.cidr, v.ttl),
    onMutate: async (v) => {
      await qc.cancelQueries({ queryKey: ['blocks'] });
      const prev = qc.getQueryData<Block[]>(['blocks']);
      if (prev) {
        const st = qc.getQueryState(['blocks']);
        const elapsed = st ? Math.floor((Date.now() - st.dataUpdatedAt) / 1000) : 0;
        const aged = prev.map((b) => ({ ...b, ttl_secs: Math.max(0, b.ttl_secs - elapsed) }));
        qc.setQueryData<Block[]>(['blocks'], [...aged.filter((b) => b.cidr !== v.cidr), { cidr: v.cidr, ttl_secs: parseTtl(v.ttl) ?? 0 }]);
      }
      return { prev };
    },
    onError: (_e, _v, ctx) => {
      if (ctx?.prev) qc.setQueryData(['blocks'], ctx.prev);
    },
    onSettled: () => {
      void qc.invalidateQueries({ queryKey: ['blocks'] });
      void qc.invalidateQueries({ queryKey: ['status'] });
    },
  }));
}

export function useRemoveBlock() {
  const qc = useQueryClient();
  return useMutation(() => ({
    mutationFn: (cidr: string) => removeBlock(cidr),
    onMutate: async (cidr) => {
      await qc.cancelQueries({ queryKey: ['blocks'] });
      const prev = qc.getQueryData<Block[]>(['blocks']);
      if (prev) qc.setQueryData<Block[]>(['blocks'], prev.filter((b) => b.cidr !== cidr));
      return { prev };
    },
    onError: (_e, _v, ctx) => {
      if (ctx?.prev) qc.setQueryData(['blocks'], ctx.prev);
    },
    onSettled: () => {
      void qc.invalidateQueries({ queryKey: ['blocks'] });
      void qc.invalidateQueries({ queryKey: ['status'] });
    },
  }));
}
