using RepositoryLayer.Repositories.Interface;
using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;

namespace RepositoryLayer.Repositories.Implementation
{
    public class UnitOfWork : IUnitOfWork
    {
        private readonly MiniNetworkDBContext context;
        public UnitOfWork(MiniNetworkDBContext context)
        {
            this.context = context;

        }
        public async Task CompleteAsync()
        {
            await context.SaveChangesAsync();
        }
    }
}
