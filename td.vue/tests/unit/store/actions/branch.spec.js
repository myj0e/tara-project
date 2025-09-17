import { BRANCH_CLEAR, BRANCH_FETCH, BRANCH_SELECTED } from '@/store/actions/branch.js';

describe('store/actions/branch.js', () => {
    it('defines a clear action', () => {
        expect(BRANCH_CLEAR).not.toBeUndefined();
    });

    it('defines a fetch action', () => {
        expect(BRANCH_FETCH).not.toBeUndefined();
    });

    it('defines a selected action', () => {
        expect(BRANCH_SELECTED).not.toBeUndefined();
    });
});
