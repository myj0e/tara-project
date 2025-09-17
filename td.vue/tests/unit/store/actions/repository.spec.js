import { REPOSITORY_CLEAR, REPOSITORY_FETCH, REPOSITORY_SELECTED } from '@/store/actions/repository.js';

describe('store/actions/repository.js', () => {
    it('defines a clear action', () => {
        expect(REPOSITORY_CLEAR).not.toBeUndefined();
    });
    
    it('defines a fetch action', () => {
        expect(REPOSITORY_FETCH).not.toBeUndefined();
    });
    
    it('defines a selected action', () => {
        expect(REPOSITORY_SELECTED).not.toBeUndefined();
    }); 
});
